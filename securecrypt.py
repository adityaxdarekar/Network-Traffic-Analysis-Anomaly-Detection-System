#!/usr/bin/env python3
"""
==============================================================================
 SecureCrypt - Secure File Encryption & Decryption Tool  (single-file project)
==============================================================================
This one file is the complete project:
  * the tool        encrypt / decrypt / info commands
  * the docs        this header
  * the test suite  python securecrypt.py selftest

Requirements: Python 3.9+  and  pip install cryptography
------------------------------------------------------------------------------

# SecureCrypt — Secure File Encryption & Decryption Tool

A command-line tool that encrypts and decrypts files with **AES-256-GCM**, using a key derived from a password with **scrypt**. It handles files of any size by streaming them in chunks, and it detects tampering, truncation and wrong passwords.

## Features

- **Authenticated encryption:** AES-256-GCM provides confidentiality and integrity in one step.
- **Memory-hard key derivation:** scrypt (N=2¹⁷, r=8, p=1 by default) with a random 16-byte salt per file makes password brute-forcing expensive.
- **Streaming:** 64 KiB chunks, so even very large files use little memory.
- **Tamper detection:** catches modified bytes, edited headers, reordered chunks, truncated files and appended data.
- **Safe output:** results go to a temp file and are renamed into place only after every chunk verifies, so a failed decryption never leaves partial plaintext on disk.
- **Password handling:** interactive prompt with confirmation, minimum length, and warnings for weak passwords. Also reads from a file or environment variable for scripting.
- **Batch mode:** encrypt or decrypt several files in one command.
- **`info` command:** shows a file's metadata without needing the password.
- Encrypted files are created with `600` permissions (owner-only).

## Requirements

- Python 3.9+
- `cryptography` library

```bash
pip install cryptography
```

## Usage

```bash
# Encrypt (prompts for password twice)
python securecrypt.py encrypt report.pdf
# -> report.pdf.sfe

# Decrypt
python securecrypt.py decrypt report.pdf.sfe
# -> report.pdf

# Custom output name, overwrite if it exists
python securecrypt.py decrypt report.pdf.sfe -o restored.pdf --force

# Several files at once, delete the originals afterwards
python securecrypt.py encrypt *.csv --remove-original

# Stronger (slower) key derivation
python securecrypt.py encrypt keys.txt --log-n 19

# Non-interactive (scripts / CI)
export SC_PW='my-long-passphrase'
python securecrypt.py encrypt data.db --password-env SC_PW
python securecrypt.py decrypt data.db.sfe --password-file ~/.secret_pw

# Inspect an encrypted file
python securecrypt.py info data.db.sfe
```

Example output:

```
[+] Encrypted demo.txt -> demo.txt.sfe (33 B)

demo.txt.sfe
  format                 SecureCrypt v1
  cipher                 AES-256-GCM
  kdf                    scrypt (N=2^17, r=8, p=1)
  chunk_size             65536
  chunks                 1
  encrypted_size         86
  approx_plaintext_size  33
  salt                   efa12335576970369f8d31126a15efda

[-] demo.txt.sfe: Decryption failed: wrong password, or the file was modified.
```

Exit codes: `0` success, `1` one or more files failed, `2` usage or password error, `130` cancelled.

## How it works

### File format (`.sfe`)

```
+---------------------------- HEADER (37 bytes) ----------------------------+
| magic "SFE1" | ver | log2N | r | p | chunk size | salt (16) | nonce pfx (8) | pad |
+----------------------------------------------------------------------------+
| chunk 0: AES-GCM ciphertext + 16-byte tag                                  |
| chunk 1: ...                                                               |
| chunk n (final)                                                            |
+----------------------------------------------------------------------------+
```

1. **Key:** `scrypt(password, salt, N, r, p) -> 256-bit key`. The salt and cost parameters are stored in the header, so decryption can derive the same key.
2. **Nonce per chunk:** `random 8-byte prefix || 4-byte chunk index`. A nonce is never reused under a key, and every chunk is bound to its position.
3. **Associated data per chunk:** `full header || is_last flag`.
   - Changing any header byte breaks authentication.
   - Dropping the final chunk fails: the new last chunk was encrypted with `is_last = 0`.
   - Appending data fails: the real final chunk was encrypted with `is_last = 1`.

### Threats covered

| Attack | Result |
|---|---|
| Wrong password | Rejected at chunk 0 |
| Flipping a bit in the ciphertext | GCM tag check fails |
| Editing the salt or KDF parameters | Header is in the AAD, so it fails |
| Swapping or reordering chunks | Nonce includes the index, so it fails |
| Truncating the file | `is_last` flag mismatch, so it fails |
| Appending data | `is_last` flag mismatch, so it fails |
| Malicious header asking for huge scrypt memory | Parameters are range-checked before use |

### Limitations

- `--remove-original` performs a normal delete, **not** a secure wipe. On SSDs and journaling filesystems, secure deletion can't be guaranteed from user space.
- Security depends on the password. Use a long passphrase.
- File names and approximate sizes are not hidden.
- The password lives in Python memory while the tool runs, and Python can't reliably zero memory.

## Running the tests

```bash
python securecrypt.py selftest      # add -v for each test name
```

22 tests: round-trips (empty, exact chunk boundary, multi-chunk, Unicode passwords),
every attack in the table above, atomic output, permissions, overwrite protection, CLI.

## Skills demonstrated

Applied cryptography (AEAD, KDFs, nonce management), secure file-format design, defending against tampering and truncation, safe file I/O, CLI design and security-focused testing.

------------------------------------------------------------------------------
IMPLEMENTATION NOTES

File format (.sfe):
    HEADER (37 bytes)
      magic        4 bytes   b"SFE1"
      version      1 byte    0x01
      scrypt log2N 1 byte    e.g. 17  -> N = 2**17
      scrypt r     1 byte
      scrypt p     1 byte
      chunk size   4 bytes   big-endian, plaintext bytes per chunk
      salt        16 bytes   random, for scrypt
      nonce prefix 8 bytes   random, combined with a 4-byte chunk counter
      (pad)        1 byte    reserved, 0x00
    CHUNKS
      each = AES-GCM(ciphertext || 16-byte tag)

Security properties:
  * Confidentiality + integrity: AES-256-GCM authenticated encryption.
  * Brute-force resistance: scrypt (memory-hard) key derivation, random salt.
  * Header tampering detected: the full header is bound as associated data.
  * Chunk reordering detected: each chunk's nonce includes its index.
  * Truncation / appending detected: the final chunk is flagged in the
    associated data, so dropping or adding chunks fails authentication.
  * No partial plaintext left behind: output goes to a temp file and is only
    renamed into place after every chunk has verified.
"""

from __future__ import annotations

import argparse
import getpass
import os
import struct
import sys
import tempfile
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

__version__ = "1.0.0"

MAGIC = b"SFE1"
VERSION = 1
EXTENSION = ".sfe"

# scrypt defaults: N=2^17, r=8, p=1  (~128 MiB RAM, ~0.3-1 s per derivation)
DEFAULT_LOG_N = 17
DEFAULT_R = 8
DEFAULT_P = 1

DEFAULT_CHUNK_SIZE = 64 * 1024
SALT_LEN = 16
NONCE_PREFIX_LEN = 8
TAG_LEN = 16
KEY_LEN = 32
MAX_CHUNKS = 2**32  # 4-byte counter

HEADER_STRUCT = struct.Struct(">4sBBBBI16s8sx")
HEADER_LEN = HEADER_STRUCT.size  # 37

MIN_PASSWORD_LEN = 8


class SecureCryptError(Exception):
    """Raised for any user-facing encryption/decryption failure."""


@dataclass(frozen=True)
class Header:
    log_n: int
    r: int
    p: int
    chunk_size: int
    salt: bytes
    nonce_prefix: bytes

    def pack(self) -> bytes:
        return HEADER_STRUCT.pack(
            MAGIC, VERSION, self.log_n, self.r, self.p,
            self.chunk_size, self.salt, self.nonce_prefix,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "Header":
        if len(data) < HEADER_LEN:
            raise SecureCryptError("File is too short to be a SecureCrypt file.")
        magic, version, log_n, r, p, chunk_size, salt, prefix = HEADER_STRUCT.unpack(data)
        if magic != MAGIC:
            raise SecureCryptError("Not a SecureCrypt file (bad magic bytes).")
        if version != VERSION:
            raise SecureCryptError(f"Unsupported file version {version}.")
        # Sanity limits so a malicious header can't make us allocate absurd memory.
        if not (10 <= log_n <= 22 and 1 <= r <= 32 and 1 <= p <= 16):
            raise SecureCryptError("Invalid key-derivation parameters in header.")
        if not (1024 <= chunk_size <= 16 * 1024 * 1024):
            raise SecureCryptError("Invalid chunk size in header.")
        return cls(log_n, r, p, chunk_size, salt, prefix)


# --------------------------------------------------------------------------- #
# Core crypto
# --------------------------------------------------------------------------- #

def derive_key(password: str, header: Header) -> bytes:
    kdf = Scrypt(salt=header.salt, length=KEY_LEN,
                 n=2**header.log_n, r=header.r, p=header.p)
    return kdf.derive(password.encode("utf-8"))


def _nonce(prefix: bytes, index: int) -> bytes:
    if index >= MAX_CHUNKS:
        raise SecureCryptError("File too large (chunk counter exhausted).")
    return prefix + index.to_bytes(4, "big")


def _aad(header_bytes: bytes, is_last: bool) -> bytes:
    return header_bytes + (b"\x01" if is_last else b"\x00")


def encrypt_stream(src, dst, password: str, *,
                   log_n: int = DEFAULT_LOG_N, r: int = DEFAULT_R, p: int = DEFAULT_P,
                   chunk_size: int = DEFAULT_CHUNK_SIZE) -> int:
    """Encrypt from file object src to dst. Returns plaintext bytes processed."""
    header = Header(log_n, r, p, chunk_size,
                    os.urandom(SALT_LEN), os.urandom(NONCE_PREFIX_LEN))
    header_bytes = header.pack()
    aes = AESGCM(derive_key(password, header))
    dst.write(header_bytes)

    total = 0
    index = 0
    current = src.read(chunk_size)
    while True:
        nxt = src.read(chunk_size)          # read ahead to know if this is last
        is_last = not nxt
        dst.write(aes.encrypt(_nonce(header.nonce_prefix, index),
                              current, _aad(header_bytes, is_last)))
        total += len(current)
        if is_last:
            return total
        current = nxt
        index += 1


def decrypt_stream(src, dst, password: str) -> int:
    """Decrypt from file object src to dst. Returns plaintext bytes produced."""
    header_bytes = src.read(HEADER_LEN)
    header = Header.unpack(header_bytes)
    aes = AESGCM(derive_key(password, header))
    enc_chunk = header.chunk_size + TAG_LEN

    total = 0
    index = 0
    current = src.read(enc_chunk)
    if not current:
        raise SecureCryptError("File is truncated (no encrypted data).")
    while True:
        nxt = src.read(enc_chunk)
        is_last = not nxt
        try:
            plain = aes.decrypt(_nonce(header.nonce_prefix, index),
                                current, _aad(header_bytes, is_last))
        except InvalidTag:
            if index == 0:
                raise SecureCryptError(
                    "Decryption failed: wrong password, or the file was modified.")
            raise SecureCryptError(
                f"Integrity check failed at chunk {index}: "
                "the file was modified or truncated.")
        dst.write(plain)
        total += len(plain)
        if is_last:
            return total
        current = nxt
        index += 1


# --------------------------------------------------------------------------- #
# File-level helpers (atomic output)
# --------------------------------------------------------------------------- #

def _atomic_write(output_path: str, force: bool, writer) -> int:
    if os.path.exists(output_path) and not force:
        raise SecureCryptError(f"Output exists: {output_path} (use --force to overwrite).")
    out_dir = os.path.dirname(os.path.abspath(output_path))
    fd, tmp = tempfile.mkstemp(prefix=".sfe-", dir=out_dir)
    try:
        with os.fdopen(fd, "wb") as dst:
            n = writer(dst)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp, output_path)
        return n
    except BaseException:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        raise


def encrypt_file(input_path: str, output_path: str, password: str,
                 force: bool = False, **kdf_opts) -> int:
    with open(input_path, "rb") as src:
        n = _atomic_write(output_path, force,
                          lambda dst: encrypt_stream(src, dst, password, **kdf_opts))
    try:
        os.chmod(output_path, 0o600)
    except OSError:
        pass
    return n


def decrypt_file(input_path: str, output_path: str, password: str,
                 force: bool = False) -> int:
    with open(input_path, "rb") as src:
        return _atomic_write(output_path, force,
                             lambda dst: decrypt_stream(src, dst, password))


def read_info(input_path: str) -> dict:
    with open(input_path, "rb") as f:
        h = Header.unpack(f.read(HEADER_LEN))
    size = os.path.getsize(input_path)
    body = size - HEADER_LEN
    enc_chunk = h.chunk_size + TAG_LEN
    chunks = max(1, -(-body // enc_chunk))
    return {
        "format": f"SecureCrypt v{VERSION}",
        "cipher": "AES-256-GCM",
        "kdf": f"scrypt (N=2^{h.log_n}, r={h.r}, p={h.p})",
        "chunk_size": h.chunk_size,
        "chunks": chunks,
        "encrypted_size": size,
        "approx_plaintext_size": max(0, body - chunks * TAG_LEN),
        "salt": h.salt.hex(),
    }


# --------------------------------------------------------------------------- #
# Password handling
# --------------------------------------------------------------------------- #

def password_warnings(password: str) -> list[str]:
    warnings = []
    if len(password) < 12:
        warnings.append("shorter than 12 characters")
    classes = sum([any(c.islower() for c in password),
                   any(c.isupper() for c in password),
                   any(c.isdigit() for c in password),
                   any(not c.isalnum() for c in password)])
    if classes < 3 and len(password) < 16:
        warnings.append("uses fewer than 3 character types (lower/upper/digit/symbol)")
    return warnings


def get_password(args, confirm: bool) -> str:
    if args.password_file:
        with open(args.password_file, "r", encoding="utf-8") as f:
            pw = f.readline().rstrip("\r\n")
    elif args.password_env:
        pw = os.environ.get(args.password_env)
        if pw is None:
            raise SecureCryptError(f"Environment variable {args.password_env} is not set.")
    else:
        pw = getpass.getpass("Password: ")
        if confirm and getpass.getpass("Confirm password: ") != pw:
            raise SecureCryptError("Passwords do not match.")
    if not pw:
        raise SecureCryptError("Password must not be empty.")
    if confirm and len(pw) < MIN_PASSWORD_LEN:
        raise SecureCryptError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    return pw


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def _default_decrypt_name(path: str) -> str:
    if path.endswith(EXTENSION):
        return path[: -len(EXTENSION)]
    return path + ".decrypted"


def cmd_encrypt(args) -> int:
    if args.output and len(args.files) > 1:
        raise SecureCryptError("-o/--output can only be used with a single input file.")
    password = get_password(args, confirm=True)
    for w in password_warnings(password):
        print(f"[!] Weak password: {w}", file=sys.stderr)
    failures = 0
    for path in args.files:
        out = args.output or path + EXTENSION
        try:
            n = encrypt_file(path, out, password, force=args.force, log_n=args.log_n)
            print(f"[+] Encrypted {path} -> {out} ({_human(n)})")
            if args.remove_original:
                os.remove(path)
                print(f"    removed original {path} (note: not a secure wipe)")
        except (SecureCryptError, OSError) as e:
            print(f"[-] {path}: {e}", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


def cmd_decrypt(args) -> int:
    if args.output and len(args.files) > 1:
        raise SecureCryptError("-o/--output can only be used with a single input file.")
    password = get_password(args, confirm=False)
    failures = 0
    for path in args.files:
        out = args.output or _default_decrypt_name(path)
        try:
            n = decrypt_file(path, out, password, force=args.force)
            print(f"[+] Decrypted {path} -> {out} ({_human(n)})")
        except (SecureCryptError, OSError) as e:
            print(f"[-] {path}: {e}", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


def cmd_info(args) -> int:
    failures = 0
    for path in args.files:
        try:
            info = read_info(path)
            print(f"{path}")
            for k, v in info.items():
                print(f"  {k:<22} {v}")
        except (SecureCryptError, OSError) as e:
            print(f"[-] {path}: {e}", file=sys.stderr)
            failures += 1
    return 1 if failures else 0



# =========================================================================== #
# Built-in test suite   ->   python securecrypt.py selftest
# =========================================================================== #
import io
import unittest

FAST = {"log_n": 14}  # low scrypt cost so tests run quickly
PW = "Correct-Horse-Battery-9"


def enc(data: bytes, pw=PW, chunk_size=1024) -> bytes:
    out = io.BytesIO()
    encrypt_stream(io.BytesIO(data), out, pw, chunk_size=chunk_size, **FAST)
    return out.getvalue()


def dec(blob: bytes, pw=PW) -> bytes:
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(blob), out, pw)
    return out.getvalue()


class RoundTrip(unittest.TestCase):
    def test_small(self):
        self.assertEqual(dec(enc(b"hello world")), b"hello world")

    def test_empty(self):
        self.assertEqual(dec(enc(b"")), b"")

    def test_exact_chunk_boundary(self):
        data = os.urandom(1024 * 3)
        self.assertEqual(dec(enc(data)), data)

    def test_multi_chunk(self):
        data = os.urandom(1024 * 10 + 37)
        self.assertEqual(dec(enc(data)), data)

    def test_unicode_password(self):
        self.assertEqual(dec(enc(b"x", pw="пароль-密码-🔑"), pw="пароль-密码-🔑"), b"x")

    def test_same_input_different_ciphertext(self):
        self.assertNotEqual(enc(b"same"), enc(b"same"))  # random salt + nonce


class Attacks(unittest.TestCase):
    def setUp(self):
        self.data = os.urandom(1024 * 4 + 100)  # 5 chunks
        self.blob = enc(self.data)

    def assertRejected(self, blob, pw=PW):
        with self.assertRaises(SecureCryptError):
            dec(blob, pw)

    def test_wrong_password(self):
        self.assertRejected(self.blob, pw="wrong-password")

    def test_bitflip_in_ciphertext(self):
        b = bytearray(self.blob)
        b[HEADER_LEN + 2000] ^= 0x01
        self.assertRejected(bytes(b))

    def test_header_tamper(self):
        b = bytearray(self.blob)
        b[20] ^= 0x01  # inside salt
        self.assertRejected(bytes(b))

    def test_truncation_drop_last_chunk(self):
        enc_chunk = 1024 + TAG_LEN
        self.assertRejected(self.blob[: HEADER_LEN + enc_chunk * 4])

    def test_truncation_partial(self):
        self.assertRejected(self.blob[:-5])

    def test_appended_data(self):
        self.assertRejected(self.blob + b"\x00" * 50)

    def test_chunk_swap(self):
        enc_chunk = 1024 + TAG_LEN
        h, body = self.blob[: HEADER_LEN], self.blob[HEADER_LEN:]
        c = [body[i:i + enc_chunk] for i in range(0, len(body), enc_chunk)]
        c[0], c[1] = c[1], c[0]
        self.assertRejected(h + b"".join(c))

    def test_not_a_securecrypt_file(self):
        self.assertRejected(b"PK\x03\x04" + os.urandom(100))

    def test_header_only(self):
        self.assertRejected(self.blob[: HEADER_LEN])


class FileLevel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.plain = os.path.join(self.d, "secret.txt")
        with open(self.plain, "wb") as f:
            f.write(b"top secret\n" * 1000)

    def tearDown(self):
        self.tmp.cleanup()

    def test_file_roundtrip_and_permissions(self):
        e = self.plain + ".sfe"
        encrypt_file(self.plain, e, PW, **FAST)
        self.assertEqual(os.stat(e).st_mode & 0o777, 0o600)
        out = os.path.join(self.d, "out.txt")
        decrypt_file(e, out, PW)
        with open(out, "rb") as a, open(self.plain, "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_refuses_overwrite_without_force(self):
        e = self.plain + ".sfe"
        encrypt_file(self.plain, e, PW, **FAST)
        with self.assertRaises(SecureCryptError):
            encrypt_file(self.plain, e, PW, **FAST)
        encrypt_file(self.plain, e, PW, force=True, **FAST)

    def test_failed_decrypt_leaves_no_output(self):
        e = self.plain + ".sfe"
        encrypt_file(self.plain, e, PW, **FAST)
        out = os.path.join(self.d, "out.txt")
        with self.assertRaises(SecureCryptError):
            decrypt_file(e, out, "wrong-password")
        self.assertFalse(os.path.exists(out))
        self.assertEqual([f for f in os.listdir(self.d) if f.startswith(".sfe-")], [])

    def test_info(self):
        e = self.plain + ".sfe"
        encrypt_file(self.plain, e, PW, **FAST)
        info = read_info(e)
        self.assertEqual(info["cipher"], "AES-256-GCM")
        self.assertEqual(info["approx_plaintext_size"], 11000)

    def test_cli_with_env_password(self):
        os.environ["SC_TEST_PW"] = PW
        try:
            rc = main(["encrypt", self.plain, "--password-env", "SC_TEST_PW", "--log-n", "14"])
            self.assertEqual(rc, 0)
            os.remove(self.plain)
            rc = main(["decrypt", self.plain + ".sfe", "--password-env", "SC_TEST_PW"])
            self.assertEqual(rc, 0)
            with open(self.plain, "rb") as f:
                self.assertEqual(f.read(), b"top secret\n" * 1000)
        finally:
            del os.environ["SC_TEST_PW"]


class PasswordChecks(unittest.TestCase):
    def test_weak(self):
        self.assertTrue(password_warnings("abcdefgh"))

    def test_strong(self):
        self.assertEqual(password_warnings("Correct-Horse-Battery-9"), [])


def cmd_selftest(args) -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for case in (RoundTrip, Attacks, FileLevel, PasswordChecks):
        suite.addTests(loader.loadTestsFromTestCase(case))
    result = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    return 0 if result.wasSuccessful() else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securecrypt",
        description="Encrypt and decrypt files with AES-256-GCM + scrypt.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_pw_opts(p):
        g = p.add_mutually_exclusive_group()
        g.add_argument("--password-file", metavar="PATH",
                       help="read password from first line of a file")
        g.add_argument("--password-env", metavar="VAR",
                       help="read password from an environment variable")
        p.add_argument("-o", "--output", help="output path (single input only)")
        p.add_argument("-f", "--force", action="store_true",
                       help="overwrite output if it exists")

    e = sub.add_parser("encrypt", help="encrypt one or more files")
    e.add_argument("files", nargs="+")
    add_pw_opts(e)
    e.add_argument("--log-n", type=int, default=DEFAULT_LOG_N, choices=range(14, 21),
                   metavar="{14..20}",
                   help=f"scrypt cost as log2(N) (default {DEFAULT_LOG_N}); higher = slower brute force")
    e.add_argument("--remove-original", action="store_true",
                   help="delete the plaintext file after successful encryption")
    e.set_defaults(func=cmd_encrypt)

    d = sub.add_parser("decrypt", help="decrypt one or more .sfe files")
    d.add_argument("files", nargs="+")
    add_pw_opts(d)
    d.set_defaults(func=cmd_decrypt)

    i = sub.add_parser("info", help="show metadata of encrypted files (no password needed)")
    i.add_argument("files", nargs="+")
    i.set_defaults(func=cmd_info)

    t = sub.add_parser("selftest", help="run the built-in test suite (22 tests)")
    t.add_argument("-v", "--verbose", action="store_true", help="show each test")
    t.set_defaults(func=cmd_selftest)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except SecureCryptError as e:
        print(f"[-] {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[-] Cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
