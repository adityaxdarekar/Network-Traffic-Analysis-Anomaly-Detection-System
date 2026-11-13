#!/usr/bin/env python3
"""
==============================================================================
 LeakHunter - Sensitive Information / Data Leak Scanner   (single-file project)
==============================================================================
This one file is the complete project:
  * the tool        scan files and folders for leaked secrets and personal data
  * the docs        this header
  * the test suite  python leakhunter.py selftest

Requirements: Python 3.9+   (standard library only, nothing to install)
------------------------------------------------------------------------------

WHAT IT DOES
  Walks through files and folders (source code, configs, .env files, logs,
  CSV exports ...) and reports anything that should not be there:

  Secrets & credentials
    * Private keys (RSA, EC, DSA, OpenSSH, PGP)
    * AWS access key IDs and secret keys
    * GitHub, GitLab, Slack, Stripe, Google, SendGrid, Twilio, npm, OpenAI tokens
    * Slack / Discord webhooks
    * Database URLs with embedded passwords (postgres://user:pass@host)
    * JSON Web Tokens (JWT) - header is decoded to confirm it is real
    * Hard-coded passwords / API keys in assignments  (password = "...")
    * High-entropy strings assigned to secret-looking names
  Personal data (PII)
    * Credit card numbers   - validated with the Luhn checksum + card prefixes
    * US Social Security numbers - invalid ranges (000, 666, 9xx) rejected
    * IBAN bank accounts    - validated with the ISO 13616 mod-97 check
    * Email addresses and phone numbers

  False-positive control
    * Validators (Luhn, mod-97, JWT decoding, entropy) instead of regex alone
    * Placeholders are ignored: changeme, your_api_key, <token>, ${VAR},
      os.environ[...], process.env..., xxxx, example values
    * Add  leakhunter:ignore  to a line to suppress it
    * Skips binary files, huge files and folders like .git, node_modules, venv

  Safe reporting
    * Secrets are MASKED in every output (terminal, JSON, CSV, SARIF):
      AKIAQ3EG**********6N  - a report never re-leaks the secret it found

SEVERITY
  critical  private keys, cloud/root credentials, live payment keys
  high      API tokens, passwords, DB credentials, credit cards, SSNs
  medium    JWTs, high-entropy secrets, IBANs, webhooks
  low       email addresses, phone numbers

USAGE
  python leakhunter.py scan .                         # scan current folder
  python leakhunter.py scan app/ config.yml .env      # files and folders
  python leakhunter.py scan . --min-severity high     # hide medium/low
  python leakhunter.py scan . --no-pii                # secrets only
  python leakhunter.py scan . --json out.json --csv out.csv
  python leakhunter.py scan . --sarif out.sarif       # GitHub code scanning
  python leakhunter.py scan . --fail-on high          # CI: exit 1 on high+
  python leakhunter.py scan . --exclude "*.test.js" --exclude "docs/*"
  python leakhunter.py rules                          # list all detectors
  python leakhunter.py selftest -v

  Exit codes: 0 nothing at/above --fail-on (default: low, i.e. any finding
  fails), 1 findings found, 2 bad input.

  Pre-commit hook example (.git/hooks/pre-commit):
      #!/bin/sh
      python leakhunter.py scan $(git diff --cached --name-only) --fail-on high

LIMITATIONS
  * Pattern-based: it can miss secrets in unusual formats and can still
    flag test data. Review findings; don't treat a clean scan as proof.
  * Scans the current files only, not git history. A secret deleted in a
    later commit is still in history: rotate it, don't just delete it.
  * Phone and email detection is tuned to avoid noise, not to catch every
    international format.
"""

from __future__ import annotations

import argparse
import base64
import csv
import fnmatch
import json
import math
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from typing import Callable, Iterable

__version__ = "1.0.0"

CRITICAL, HIGH, MEDIUM, LOW = "critical", "high", "medium", "low"
SEV_RANK = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
SECRET, PII = "secret", "pii"

DEFAULT_EXCLUDED_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
                         "env", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".idea",
                         ".vscode", "vendor", "bower_components", ".terraform"}
BINARY_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf", ".zip",
                     ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".class", ".exe",
                     ".dll", ".so", ".dylib", ".o", ".a", ".pyc", ".woff", ".woff2", ".ttf", ".otf",
                     ".mp3", ".mp4", ".mov", ".avi", ".wav", ".sqlite", ".db", ".docx", ".xlsx"}
MAX_FILE_BYTES = 5 * 1024 * 1024
IGNORE_MARKER = "leakhunter:ignore"


# =========================================================================== #
# Validators
# =========================================================================== #

def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


CARD_PREFIX = re.compile(r"^(4\d{12}(\d{3})?(\d{3})?"            # Visa
                         r"|5[1-5]\d{14}|2(2[2-9]|[3-6]\d|7[01])\d{12}|2720\d{12}"  # Mastercard
                         r"|3[47]\d{13}"                          # Amex
                         r"|6(011|5\d\d)\d{12,15}"                # Discover
                         r"|3(0[0-5]|[68]\d)\d{11}"               # Diners
                         r"|35(2[89]|[3-8]\d)\d{12,15})$")       # JCB


def valid_card(value: str) -> bool:
    digits = re.sub(r"[ -]", "", value)
    if not (13 <= len(digits) <= 19) or len(set(digits)) < 4:
        return False
    return bool(CARD_PREFIX.match(digits)) and luhn_ok(digits)


def valid_iban(value: str) -> bool:
    v = value.replace(" ", "").upper()
    if not (15 <= len(v) <= 34):
        return False
    rearranged = v[4:] + v[:4]
    num = "".join(str(int(c, 36)) for c in rearranged)
    return int(num) % 97 == 1


def valid_jwt(value: str) -> bool:
    try:
        head = value.split(".")[0]
        head += "=" * (-len(head) % 4)
        data = json.loads(base64.urlsafe_b64decode(head))
        return isinstance(data, dict) and "alg" in data
    except Exception:
        return False


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def high_entropy(value: str) -> bool:
    if len(value) < 20:
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return shannon_entropy(value) >= 3.0
    if not re.search(r"\d", value) or re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)+", value):
        return False  # real random tokens contain digits; dotted names are code
    has_mix = bool(re.search(r"[a-z]", value) and re.search(r"[A-Z0-9]", value))
    return has_mix and shannon_entropy(value) >= 3.7


PLACEHOLDER = re.compile(
    r"^(?:x+|\*+|\.+|0+|1234\w*|changeme|change_me|password|passw0rd|secret|redacted|"
    r"none|null|nil|undefined|true|false|todo|tbd|test\w*|dummy\w*|fake\w*|sample\w*|example\w*|"
    r"placeholder|your[_-]?\w*|my[_-]?\w*|insert\w*|replace\w*|enter\w*|<[^>]*>|\{\{.*\}\}|"
    r"\$\{?[\w.]+\}?|%\(?\w+\)?s?|env\(.*|process\.env.*|os\.environ.*|getenv.*|config\[.*|"
    r"settings\.\w+|\w+\.get\(.*)$", re.I)


def is_placeholder(value: str) -> bool:
    v = value.strip("'\"` ")
    if not v or PLACEHOLDER.match(v):
        return True
    if re.search(r"example|placeholder|dummy|xxxx|your[_-]|<.+>|\$\{|\{\d*\}|%s|%\(\w+\)", v, re.I):
        return True
    return False


# =========================================================================== #
# Rules
# =========================================================================== #

@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    severity: str
    pattern: re.Pattern
    group: int = 0                     # regex group that holds the sensitive value
    validator: Callable[[str], bool] | None = None
    skip_placeholders: bool = False
    description: str = ""


def R(id, name, cat, sev, regex, group=0, validator=None, flags=0, placeholders=False, desc=""):
    return Rule(id, name, cat, sev, re.compile(regex, flags), group, validator, placeholders, desc)


SECRET_NAME = r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|" \
              r"private[_-]?key|client[_-]?secret|auth[_-]?key|credentials?)"

RULES: list[Rule] = [
    # ---- critical -----------------------------------------------------------
    R("private-key", "Private key", SECRET, CRITICAL,
      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
      desc="Anyone with this key can impersonate the server/user it belongs to."),
    R("aws-secret-key", "AWS secret access key", SECRET, CRITICAL,
      r"(?i)aws_?secret_?(?:access_?)?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", 1,
      placeholders=True, desc="Full programmatic access to the AWS account."),
    R("github-token", "GitHub token", SECRET, CRITICAL,
      r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,90})\b", 1),
    R("stripe-live-key", "Stripe live secret key", SECRET, CRITICAL,
      r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b", 1, desc="Can move real money."),
    # ---- high ---------------------------------------------------------------
    R("aws-access-key-id", "AWS access key ID", SECRET, HIGH,
      r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16})\b", 1,
      validator=lambda v: "EXAMPLE" not in v),
    R("gitlab-token", "GitLab token", SECRET, HIGH, r"\b(glpat-[A-Za-z0-9_-]{20})\b", 1),
    R("slack-token", "Slack token", SECRET, HIGH, r"\b(xox[abposr]-[A-Za-z0-9-]{10,72})\b", 1),
    R("google-api-key", "Google API key", SECRET, HIGH, r"\b(AIza[0-9A-Za-z_-]{35})\b", 1),
    R("sendgrid-key", "SendGrid API key", SECRET, HIGH,
      r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b", 1),
    R("twilio-key", "Twilio API key", SECRET, HIGH, r"\b(SK[0-9a-fA-F]{32})\b", 1),
    R("npm-token", "npm access token", SECRET, HIGH, r"\b(npm_[A-Za-z0-9]{36})\b", 1),
    R("openai-key", "OpenAI API key", SECRET, HIGH,
      r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,})\b", 1, validator=high_entropy),
    R("db-url-password", "Database URL with password", SECRET, HIGH,
      r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql|sqlserver)"
      r"://[^\s:/@\"']+:([^\s@/\"']+)@", 1, placeholders=True),
    R("hardcoded-password", "Hard-coded password / secret", SECRET, HIGH,
      r"(?i)[\"']?\b[\w.-]*" + SECRET_NAME + r"\b[\"']?\s*(?::=|=>|[:=])\s*[\"']([^\"'\s]{6,})[\"']", 1,
      placeholders=True, desc="Credentials in source code end up in git history, backups and logs."),
    R("env-secret", "Secret in .env / config assignment", SECRET, HIGH,
      r"(?m)^\s*(?:export\s+)?[A-Z0-9_]*" + SECRET_NAME.upper() +
      r"[A-Z0-9_]*\s*=\s*([^\s\"'#()\[\]{},;]{6,})\s*$", 1, placeholders=True,
      validator=lambda v: bool(re.search(r"[\d!@#$%^&*+/=~-]", v))),
    R("credit-card", "Credit card number", PII, HIGH,
      r"(?<![\d-])((?:\d[ -]?){12,18}\d)(?![\d-])", 1, validator=valid_card,
      desc="Storing card numbers in clear text breaks PCI DSS."),
    R("us-ssn", "US Social Security number", PII, HIGH,
      r"(?<![\d-])((?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4})(?![\d-])", 1),
    # ---- medium -------------------------------------------------------------
    R("jwt", "JSON Web Token", SECRET, MEDIUM,
      r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b", 1, validator=valid_jwt,
      desc="A valid session token lets someone act as that user until it expires."),
    R("slack-webhook", "Slack webhook URL", SECRET, MEDIUM,
      r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})", 1),
    R("discord-webhook", "Discord webhook URL", SECRET, MEDIUM,
      r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{50,})", 1),
    R("high-entropy-secret", "High-entropy secret", SECRET, MEDIUM,
      r"(?i)\b[\w.-]*" + SECRET_NAME + r"[\w.-]*[\"']?\s*(?::=|=>|[:=])\s*[\"']?([A-Za-z0-9+/=_.-]{20,})", 1,
      validator=high_entropy, placeholders=True),
    R("iban", "IBAN bank account", PII, MEDIUM,
      r"\b([A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?)\b", 1, validator=valid_iban),
    # ---- low ----------------------------------------------------------------
    R("email", "Email address", PII, LOW,
      r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", 1,
      validator=lambda v: not re.search(r"@(?:example\.(?:com|org|net)|test\.com|localhost|"
                                        r"[\w.-]*\.(?:png|jpg|svg|gif))$|^(?:noreply|no-reply|git)@", v, re.I)),
    R("phone", "Phone number", PII, LOW,
      r"(?<![\w+.-])((?:\+1[ .-]?)?\(?[2-9]\d{2}\)?[ .-]\d{3}[ .-]\d{4}|\+(?:[2-9]\d{0,2})[ .-]?\d{2,4}[ .-]\d{3,4}[ .-]\d{3,4})(?![\w.-])", 1,
      validator=lambda v: not re.fullmatch(r"[\d.]+", v) and "555-01" not in v),
]

RULE_BY_ID = {r.id: r for r in RULES}


# =========================================================================== #
# Scanning
# =========================================================================== #

@dataclass
class Finding:
    rule_id: str
    rule: str
    category: str
    severity: str
    file: str
    line: int
    column: int
    masked: str
    context: str


def mask(value: str) -> str:
    v = value.strip()
    if "PRIVATE KEY" in v:
        return v
    if len(v) <= 8:
        return v[0] + "*" * (len(v) - 1)
    return v[:4] + "*" * min(len(v) - 6, 16) + v[-2:]


GENERIC_RULES = {"hardcoded-password", "env-secret", "high-entropy-secret", "email", "phone"}


def _scan_order(rules: list[Rule]) -> list[Rule]:
    """Specific detectors first, so a JWT is reported as a JWT, not as a generic secret."""
    return sorted(rules, key=lambda r: (r.id in GENERIC_RULES, SEV_RANK[r.severity]))


def scan_text(text: str, path: str, rules: list[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    ordered = _scan_order(rules)
    for lineno, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARKER in line or len(line) > 5000:
            continue
        hits: list[tuple[int, int, Rule, str]] = []
        for rule in ordered:
            for m in rule.pattern.finditer(line):
                value = m.group(rule.group)
                if value is None:
                    continue
                start, end = m.span(rule.group)
                if any(s < end and start < e for s, e, _, _ in hits):
                    continue
                if rule.skip_placeholders and is_placeholder(value):
                    continue
                if rule.validator and not rule.validator(value):
                    continue
                hits.append((start, end, rule, value))
        if not hits:
            continue
        # Mask EVERY hit on the line before using it as context, so one finding's
        # context never reveals another finding's value.
        masked_line = line
        for start, end, _, value in sorted(hits, key=lambda h: -h[0]):
            masked_line = masked_line[:start] + mask(value) + masked_line[end:]
        context = masked_line.strip()
        if len(context) > 160:
            context = context[:157] + "..."
        for start, end, rule, value in sorted(hits, key=lambda h: h[0]):
            findings.append(Finding(rule.id, rule.name, rule.category, rule.severity,
                                    path, lineno, start + 1, mask(value), context))
    return findings


def is_binary(path: str) -> bool:
    if os.path.splitext(path)[1].lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(8192)
    except OSError:
        return True


def iter_files(targets: Iterable[str], excludes: list[str], stats: dict) -> Iterable[str]:
    def excluded(p: str) -> bool:
        rel = p.replace(os.sep, "/")
        return any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(p), pat)
                   or fnmatch.fnmatch(rel, "*/" + pat) for pat in excludes)

    for t in targets:
        if os.path.isfile(t):
            if not excluded(t):
                yield t
        elif os.path.isdir(t):
            for root, dirs, files in os.walk(t):
                dirs[:] = sorted(d for d in dirs if d not in DEFAULT_EXCLUDED_DIRS
                                 and not excluded(os.path.join(root, d)))
                for name in sorted(files):
                    p = os.path.join(root, name)
                    if not excluded(p) and not os.path.islink(p):
                        yield p
        else:
            stats["errors"].append(f"Not found: {t}")


def scan_paths(targets: list[str], rules: list[Rule], excludes: list[str] | None = None,
               max_bytes: int = MAX_FILE_BYTES) -> tuple[list[Finding], dict]:
    stats = {"files_scanned": 0, "files_skipped": 0, "bytes_scanned": 0, "errors": []}
    findings: list[Finding] = []
    t0 = time.time()
    for path in iter_files(targets, excludes or [], stats):
        try:
            size = os.path.getsize(path)
            if size > max_bytes or is_binary(path):
                stats["files_skipped"] += 1
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as e:
            stats["errors"].append(f"{path}: {e.strerror}")
            continue
        stats["files_scanned"] += 1
        stats["bytes_scanned"] += size
        findings += scan_text(text, path, rules)
    stats["seconds"] = round(time.time() - t0, 3)
    findings.sort(key=lambda f: (SEV_RANK[f.severity], f.file, f.line))
    return findings, stats


def select_rules(min_severity: str, no_pii: bool, no_secrets: bool, only: list[str] | None) -> list[Rule]:
    rules = [r for r in RULES if SEV_RANK[r.severity] <= SEV_RANK[min_severity]]
    if no_pii:
        rules = [r for r in rules if r.category != PII]
    if no_secrets:
        rules = [r for r in rules if r.category != SECRET]
    if only:
        unknown = set(only) - set(RULE_BY_ID)
        if unknown:
            raise ValueError(f"Unknown rule id(s): {', '.join(sorted(unknown))}")
        rules = [r for r in rules if r.id in only]
    return rules


# =========================================================================== #
# Output
# =========================================================================== #

class Color:
    def __init__(self, on: bool):
        c = (lambda code: (lambda s: f"\033[{code}m{s}\033[0m")) if on else (lambda code: (lambda s: s))
        self.red, self.yellow, self.blue, self.green = c("31"), c("33"), c("36"), c("32")
        self.mag, self.dim, self.bold = c("35;1"), c("2"), c("1")


def render_text(findings: list[Finding], stats: dict, col: Color) -> str:
    tag = {CRITICAL: col.mag("[CRITICAL]"), HIGH: col.red("[HIGH]    "),
           MEDIUM: col.yellow("[MEDIUM]  "), LOW: col.blue("[LOW]     ")}
    L = []
    current = None
    for f in sorted(findings, key=lambda x: (x.file, x.line, SEV_RANK[x.severity])):
        if f.file != current:
            current = f.file
            L.append("\n" + col.bold(f"{f.file}"))
        L.append(f"  {tag[f.severity]} line {f.line:<4} {f.rule}: {f.masked}")
        L.append(col.dim(f"             {f.context}"))
    L.append("\n" + col.bold("=" * 64))
    L.append(col.bold(" SUMMARY"))
    L.append(f" Files scanned: {stats['files_scanned']}   skipped: {stats['files_skipped']}   "
             f"time: {stats['seconds']}s")
    by_sev = {s: sum(1 for f in findings if f.severity == s) for s in SEV_RANK}
    L.append(f" Findings: {len(findings)}   " +
             "  ".join(f"{tag[s].strip()} {by_sev[s]}" for s in SEV_RANK))
    if findings:
        by_rule: dict[str, int] = {}
        for f in findings:
            by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
        L.append(" By type:  " + ", ".join(f"{k} ({v})" for k, v in
                                           sorted(by_rule.items(), key=lambda kv: -kv[1])))
        n_files = len({f.file for f in findings})
        L.append(f" Affected files: {n_files}")
    else:
        L.append(col.green(" No leaks found."))
    for e in stats["errors"]:
        L.append(col.yellow(f" [!] {e}"))
    if any(f.category == SECRET for f in findings):
        L.append(col.dim("\n Tip: treat every leaked secret as compromised. Rotate/revoke it first,\n"
                         " then remove it from the code and from git history."))
    return "\n".join(L)


def write_json(findings, stats, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"tool": f"LeakHunter {__version__}", "stats": stats,
                   "findings": [asdict(x) for x in findings]}, f, indent=2)


def write_csv(findings, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["severity", "category", "rule_id", "rule", "file", "line", "column", "masked_value"])
        for x in findings:
            w.writerow([x.severity, x.category, x.rule_id, x.rule, x.file, x.line, x.column, x.masked])


def write_sarif(findings, path):
    level = {CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "note"}
    used = sorted({f.rule_id for f in findings})
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "LeakHunter", "version": __version__,
                "rules": [{"id": rid, "name": RULE_BY_ID[rid].name,
                           "shortDescription": {"text": RULE_BY_ID[rid].name},
                           "properties": {"severity": RULE_BY_ID[rid].severity,
                                          "category": RULE_BY_ID[rid].category}} for rid in used]}},
            "results": [{
                "ruleId": f.rule_id, "level": level[f.severity],
                "message": {"text": f"{f.rule} found: {f.masked}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace(os.sep, "/")},
                    "region": {"startLine": f.line, "startColumn": f.column}}}],
            } for f in findings],
        }],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)


# =========================================================================== #
# CLI
# =========================================================================== #

def cmd_scan(args) -> int:
    try:
        rules = select_rules(args.min_severity, args.no_pii, args.no_secrets, args.rule)
    except ValueError as e:
        print(f"[-] {e}", file=sys.stderr)
        return 2
    findings, stats = scan_paths(args.paths, rules, args.exclude, args.max_size * 1024 * 1024)
    col = Color(sys.stdout.isatty() and not args.no_color)
    print(render_text(findings, stats, col))
    if args.json:
        write_json(findings, stats, args.json)
        print(f"\n[+] JSON report: {args.json}")
    if args.csv:
        write_csv(findings, args.csv)
        print(f"[+] CSV report: {args.csv}")
    if args.sarif:
        write_sarif(findings, args.sarif)
        print(f"[+] SARIF report: {args.sarif}")
    if stats["files_scanned"] == 0 and stats["errors"]:
        return 2
    return 1 if any(SEV_RANK[f.severity] <= SEV_RANK[args.fail_on] for f in findings) else 0


def cmd_rules(args) -> int:
    print(f"{'ID':<22}{'SEVERITY':<10}{'TYPE':<8}NAME")
    for r in RULES:
        print(f"{r.id:<22}{r.severity:<10}{r.category:<8}{r.name}")
    print(f"\n{len(RULES)} rules")
    return 0


# =========================================================================== #
# Built-in test suite   ->   python leakhunter.py selftest
# =========================================================================== #
import tempfile
import unittest

# Test secrets are built at runtime from parts so this file itself never
# contains a scannable credential (and so it doesn't trip other scanners).
_A = "AKIA" + "Q3EGRL7H4M2XPZ6N"
_AWS_SECRET = "wJalr" + "XUtnFEMI/K7MDENG/bPxRfiCYzQ9vT2Lw8H"
_GH = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
_STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
_SLACK = "xoxb-" + "1234567890-0987654321-AbCdEfGhIjKlMnOp"
_GOOGLE = "AIza" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
_PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"


def _scan(text, rules=None):
    return scan_text(text, "t.txt", rules or RULES)


def _ids(text):
    return [f.rule_id for f in _scan(text)]


class SecretRuleTests(unittest.TestCase):
    def test_private_key(self):
        self.assertEqual(_ids(_PEM), ["private-key"])

    def test_aws_keys(self):
        self.assertIn("aws-access-key-id", _ids(f"key = {_A}"))
        self.assertIn("aws-secret-key", _ids(f"aws_secret_access_key = {_AWS_SECRET}"))

    def test_aws_documentation_example_ignored(self):
        self.assertEqual(_ids("AKIA" + "IOSFODNN7EXAMPLE"), [])

    def test_vendor_tokens(self):
        self.assertIn("github-token", _ids(f"token: {_GH}"))
        self.assertIn("stripe-live-key", _ids(f"STRIPE={_STRIPE}"))
        self.assertIn("slack-token", _ids(f"slack = '{_SLACK}'"))
        self.assertIn("google-api-key", _ids(f"maps_key={_GOOGLE}"))

    def test_specific_rule_beats_generic(self):
        self.assertEqual(_ids(f'const token = "{_JWT}";'), ["jwt"])

    def test_jwt_is_decoded(self):
        self.assertIn("jwt", _ids(f"Authorization: Bearer {_JWT}"))
        fake = "eyJ" + "notreallyjson1234" + ".eyJ" + "alsonotjson12345" + ".signature12345"
        self.assertNotIn("jwt", _ids(fake))

    def test_db_url(self):
        f = _scan("DATABASE_URL=postgres://admin:S3cr3tPa55@db.internal:5432/app")
        self.assertEqual(f[0].rule_id, "db-url-password")
        self.assertNotIn("S3cr3tPa55", f[0].context)

    def test_hardcoded_password(self):
        self.assertIn("hardcoded-password", _ids('db_password = "Tr0ub4dor&3x"'))
        self.assertIn("hardcoded-password", _ids('"apiKey": "k8Fj2LmQ9xZ"'))

    def test_env_file(self):
        self.assertIn("env-secret", _ids("export API_SECRET=h7Gk2PqZ9wLm4Rt"))

    def test_high_entropy(self):
        self.assertIn("high-entropy-secret", _ids("auth_token: 9fK2mQ7vX4pL8sR1tY6wZ3bN5cH0jD"))
        self.assertEqual(_ids("auth_token: aaaaaaaaaaaaaaaaaaaaaaaa"), [])

    def test_placeholders_ignored(self):
        for line in ['password = "changeme"', 'api_key = "your_api_key_here"', "password = '${DB_PASS}'",
                     "SECRET_KEY=<your-secret>", 'token = os.environ["TOKEN"]',
                     "DATABASE_URL=postgres://user:${PASSWORD}@host/db", 'password = "example123"']:
            self.assertEqual(_ids(line), [], line)

    def test_code_is_not_a_secret(self):
        for line in ["token = get_token(name)", "TOKEN = s[1:]", "credentials = '{}:{}'.format(u, p)",
                     "user, password = HTTPPasswordMgr.find_user_password(self, realm)",
                     "PASSWORD = DEFAULT_PASSWORD"]:
            self.assertEqual(_ids(line), [], line)

    def test_ignore_marker(self):
        self.assertEqual(_ids(f"key = {_A}  # leakhunter:ignore"), [])


class PIIRuleTests(unittest.TestCase):
    def test_credit_cards_luhn(self):
        self.assertIn("credit-card", _ids("card: 4539 1488 0343 6467"))
        self.assertIn("credit-card", _ids("mc 5425-2334-3010-9903"))
        self.assertIn("credit-card", _ids("amex 3782-822463-10005"))
        self.assertNotIn("credit-card", _ids("card: 4539 1488 0343 6468"))   # bad checksum
        self.assertNotIn("credit-card", _ids("card: 4111 1111 1111 1111"))   # low-variety test number
        self.assertNotIn("credit-card", _ids("order id 1234567812345678"))   # no card prefix

    def test_ssn(self):
        self.assertIn("us-ssn", _ids("SSN: 123-45-6789"))
        for bad in ("000-12-3456", "666-12-3456", "900-12-3456", "123-00-4567", "123-45-0000"):
            self.assertNotIn("us-ssn", _ids(bad), bad)

    def test_iban(self):
        self.assertIn("iban", _ids("IBAN: DE89 3704 0044 0532 0130 00"))
        self.assertIn("iban", _ids("GB82WEST12345698765432"))
        self.assertNotIn("iban", _ids("GB82WEST12345698765433"))  # bad mod-97

    def test_email(self):
        self.assertIn("email", _ids("contact jane.doe@acme-corp.io"))
        self.assertEqual(_ids("user@example.com noreply@github.com"), [])

    def test_phone(self):
        self.assertIn("phone", _ids("call (415) 867-5309"))
        self.assertIn("phone", _ids("tel +44 20 7946 0958"))
        self.assertEqual(_ids("version 1.2.3.4 and ip 10.0.0.1"), [])


class MaskingAndReportTests(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(mask(_A), "AKIA" + "*" * 14 + "6N")
        self.assertEqual(mask("abc123"), "a*****")

    def test_context_masks_all_values_on_line(self):
        f = _scan("1,Maria,maria@acme-corp.io,(415) 867-5309,4539 1488 0343 6467,219-09-9999")
        self.assertEqual(len(f), 4)
        for x in f:
            for raw in ("4539 1488 0343 6467", "219-09-9999", "maria@acme-corp.io", "(415) 867-5309"):
                self.assertNotIn(raw, x.context)

    def test_no_secret_in_any_report(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "config.py")
            secrets = [_A, _GH, _STRIPE, "S3cr3tPa55"]
            with open(p, "w") as f:
                f.write(f"AWS_KEY = '{_A}'\nGH = '{_GH}'\nSTRIPE = '{_STRIPE}'\n"
                        "DB = 'mysql://root:S3cr3tPa55@localhost/db'\n")
            findings, stats = scan_paths([d], RULES)
            self.assertEqual(len(findings), 4)
            outs = [os.path.join(d, n) for n in ("r.json", "r.csv", "r.sarif")]
            write_json(findings, stats, outs[0])
            write_csv(findings, outs[1])
            write_sarif(findings, outs[2])
            text = render_text(findings, stats, Color(False))
            blobs = [text] + [open(o).read() for o in outs]
            for blob in blobs:
                for s in secrets:
                    self.assertNotIn(s, blob)
            sarif = json.load(open(outs[2]))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"][0]["results"]), 4)


class FileWalkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.d = self.tmp.name
        os.makedirs(os.path.join(d, "src"))
        os.makedirs(os.path.join(d, "node_modules", "pkg"))
        os.makedirs(os.path.join(d, "docs"))
        open(os.path.join(d, "src", "app.py"), "w").write(f"k = '{_A}'\n")
        open(os.path.join(d, "node_modules", "pkg", "x.js"), "w").write(f"k = '{_A}'\n")
        open(os.path.join(d, "docs", "notes.md"), "w").write(f"k = '{_A}'\n")
        open(os.path.join(d, "blob.bin"), "wb").write(b"\x00\x01" + _A.encode())
        open(os.path.join(d, "logo.png"), "wb").write(_A.encode())

    def tearDown(self):
        self.tmp.cleanup()

    def test_skips_excluded_dirs_and_binaries(self):
        f, stats = scan_paths([self.d], RULES)
        self.assertEqual(sorted(os.path.relpath(x.file, self.d) for x in f),
                         [os.path.join("docs", "notes.md"), os.path.join("src", "app.py")])
        self.assertEqual(stats["files_skipped"], 2)

    def test_exclude_glob(self):
        f, _ = scan_paths([self.d], RULES, excludes=["docs"])
        self.assertEqual([os.path.basename(x.file) for x in f], ["app.py"])

    def test_max_size(self):
        _, stats = scan_paths([self.d], RULES, max_bytes=5)
        self.assertEqual(stats["files_scanned"], 0)

    def test_missing_path_reported(self):
        _, stats = scan_paths([os.path.join(self.d, "nope")], RULES)
        self.assertTrue(stats["errors"])


class CLITests(unittest.TestCase):
    def test_exit_codes_and_filters(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.txt")
            open(p, "w").write("mail: jane.doe@acme-corp.io\n")
            devnull = open(os.devnull, "w")
            old, sys.stdout = sys.stdout, devnull
            try:
                self.assertEqual(main(["scan", p, "--no-color"]), 1)                    # low finding fails
                self.assertEqual(main(["scan", p, "--no-color", "--fail-on", "high"]), 0)
                self.assertEqual(main(["scan", p, "--no-color", "--no-pii"]), 0)
                self.assertEqual(main(["scan", p, "--no-color", "--rule", "nope"]), 2)
                self.assertEqual(main(["scan", os.path.join(d, "missing"), "--no-color"]), 2)
            finally:
                sys.stdout = old
                devnull.close()

    def test_rules_have_unique_ids(self):
        self.assertEqual(len(RULE_BY_ID), len(RULES))


def cmd_selftest(args) -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for case in (SecretRuleTests, PIIRuleTests, MaskingAndReportTests, FileWalkTests, CLITests):
        suite.addTests(loader.loadTestsFromTestCase(case))
    result = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    return 0 if result.wasSuccessful() else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="leakhunter",
                                description="Find leaked secrets and personal data in files and folders.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan files and folders")
    s.add_argument("paths", nargs="+", help="files or folders to scan")
    s.add_argument("--min-severity", choices=list(SEV_RANK), default=LOW, help="hide findings below this")
    s.add_argument("--fail-on", choices=list(SEV_RANK), default=LOW,
                   help="exit 1 if a finding at or above this severity exists (default: low)")
    s.add_argument("--no-pii", action="store_true", help="skip personal-data rules")
    s.add_argument("--no-secrets", action="store_true", help="skip secret/credential rules")
    s.add_argument("--rule", action="append", metavar="ID", help="only run these rule ids (repeatable)")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip matching files/folders (repeatable)")
    s.add_argument("--max-size", type=float, default=5, metavar="MB", help="skip files larger than this (5)")
    s.add_argument("--json", metavar="PATH")
    s.add_argument("--csv", metavar="PATH")
    s.add_argument("--sarif", metavar="PATH", help="SARIF 2.1.0 for GitHub code scanning")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("rules", help="list all detection rules")
    r.set_defaults(func=cmd_rules)

    t = sub.add_parser("selftest", help="run the built-in test suite")
    t.add_argument("-v", "--verbose", action="store_true")
    t.set_defaults(func=cmd_selftest)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[-] Cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
