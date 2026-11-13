#!/usr/bin/env python3
"""
==============================================================================
 HeaderScan - Website Security Header Checker   (single-file project)
==============================================================================
This one file is the complete project:
  * the tool        scan one or many websites, or analyse saved headers
  * the docs        this header
  * the test suite  python headerscan.py selftest

Requirements: Python 3.9+  and  pip install requests
------------------------------------------------------------------------------

WHAT IT DOES
  Fetches a website and grades its HTTP security headers, A+ to F, with a
  clear finding and fix for every problem. It checks:

  Transport
    * HTTPS in use, and HTTP -> HTTPS redirect
    * Strict-Transport-Security (max-age, includeSubDomains, preload)
  Content & framing
    * Content-Security-Policy  (missing, report-only, 'unsafe-inline',
      'unsafe-eval', wildcard / http: / data: script sources, object-src,
      base-uri, frame-ancestors)
    * X-Frame-Options (or CSP frame-ancestors) - clickjacking
    * X-Content-Type-Options: nosniff - MIME sniffing
  Privacy & isolation
    * Referrer-Policy, Permissions-Policy (and deprecated Feature-Policy)
    * Cross-Origin-Opener / Resource / Embedder-Policy
  Information disclosure
    * Server version, X-Powered-By, X-AspNet-Version, X-Generator ...
  Cookies (every Set-Cookie)
    * Secure, HttpOnly, SameSite, SameSite=None without Secure,
      __Host- / __Secure- prefix rules
  CORS
    * Access-Control-Allow-Origin: * (with or without credentials), "null"
  Deprecated headers
    * X-XSS-Protection, Expect-CT, Public-Key-Pins

SCORING
  Start at 100. Each finding deducts: high -20, medium -10, low -3, info 0.
  100 = A+   >=90 = A   >=80 = B   >=65 = C   >=50 = D   else F

USAGE
  python headerscan.py scan https://example.com
  python headerscan.py scan example.com github.com          # several sites
  python headerscan.py scan -f sites.txt --json report.json  # list + JSON
  python headerscan.py scan example.com --csv report.csv
  python headerscan.py scan example.com --min-grade B        # CI gate: exit 1 if worse
  python headerscan.py scan https://self-signed.local --insecure
  curl -sI https://example.com > h.txt
  python headerscan.py analyze h.txt                         # offline, saved headers
  python headerscan.py selftest -v

  Exit codes: 0 ok, 1 a site graded below --min-grade, 2 a site could not be
  fetched / bad input.

LIMITATIONS
  * Checks headers only; it is not a vulnerability scanner. A good grade
    means good browser-side defences, not a secure application.
  * Only the final response (after redirects) is graded; cookies set on
    intermediate redirects are not graded.
  * Some sites return different headers to different clients or pages.
    Scan the pages that matter (login, app) not just the homepage.
  * Only scan sites you own or are allowed to test. This tool sends normal
    GET requests, but your organisation's rules still apply.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Iterable
from urllib.parse import urlparse

__version__ = "1.0.0"

USER_AGENT = f"HeaderScan/{__version__} (+security header checker)"

PASS, INFO, LOW, MEDIUM, HIGH = "pass", "info", "low", "medium", "high"
PENALTY = {PASS: 0, INFO: 0, LOW: 3, MEDIUM: 10, HIGH: 20}
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3, PASS: 4}
GRADES = [(100, "A+"), (90, "A"), (80, "B"), (65, "C"), (50, "D"), (0, "F")]
GRADE_RANK = {g: i for i, (_, g) in enumerate(GRADES)}  # lower = better

ONE_YEAR = 31536000
SIX_MONTHS = 15552000


# =========================================================================== #
# Data model
# =========================================================================== #

@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str = ""
    fix: str = ""


@dataclass
class Report:
    url: str
    final_url: str
    status: int | None
    redirects: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @property
    def score(self) -> int:
        return max(0, 100 - sum(PENALTY[f.severity] for f in self.findings))

    @property
    def grade(self) -> str:
        if self.error:
            return "ERR"
        return next(g for limit, g in GRADES if self.score >= limit)

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in (HIGH, MEDIUM, LOW, INFO, PASS)}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(score=self.score, grade=self.grade, counts=self.counts())
        return d


class Headers:
    """Case-insensitive header view that keeps every Set-Cookie separately."""

    def __init__(self, pairs: Iterable[tuple[str, str]]):
        self._map: dict[str, list[str]] = {}
        self.order: list[str] = []
        for k, v in pairs:
            key = k.strip().lower()
            if key not in self._map:
                self._map[key] = []
                self.order.append(k.strip())
            self._map[key].append(v.strip())

    def get(self, name: str) -> str | None:
        vals = self._map.get(name.lower())
        return ", ".join(vals) if vals else None

    def getlist(self, name: str) -> list[str]:
        return list(self._map.get(name.lower(), []))

    def __contains__(self, name: str) -> bool:
        return name.lower() in self._map

    def as_dict(self) -> dict[str, str]:
        out = {}
        for k in self.order:
            vals = self._map[k.lower()]
            out[k] = vals[0] if len(vals) == 1 else vals  # type: ignore[assignment]
        return out


# =========================================================================== #
# Individual checks.  Each returns a list of Findings (including passes).
# =========================================================================== #

def check_https(url: str, http_redirects_to_https: bool | None) -> list[Finding]:
    out = []
    if urlparse(url).scheme != "https":
        out.append(Finding("https", HIGH, "Site is not served over HTTPS",
                           f"Final URL is {url}. All traffic, cookies and headers travel in clear text.",
                           "Serve the site over HTTPS (e.g. a free Let's Encrypt certificate) and redirect HTTP to HTTPS."))
        return out
    out.append(Finding("https", PASS, "Served over HTTPS"))
    if http_redirects_to_https is True:
        out.append(Finding("http-redirect", PASS, "HTTP redirects to HTTPS"))
    elif http_redirects_to_https is False:
        out.append(Finding("http-redirect", MEDIUM, "HTTP does not redirect to HTTPS",
                           "Visitors who type the bare domain get an unencrypted page.",
                           "Add a 301 redirect from http:// to https:// for every path."))
    return out


def _days(sec: int) -> str:
    d = sec // 86400
    return f"{d} day" if d == 1 else f"{d} days"


def check_hsts(h: Headers, url: str) -> list[Finding]:
    if urlparse(url).scheme != "https":
        return []  # HSTS is ignored by browsers over HTTP; HTTPS finding covers it
    v = h.get("Strict-Transport-Security")
    if not v:
        return [Finding("hsts", HIGH, "Strict-Transport-Security missing",
                        "Without HSTS an attacker on the network can downgrade the first visit to HTTP (SSL stripping).",
                        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")]
    directives = [d.strip().lower() for d in v.split(";") if d.strip()]
    m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
    out = []
    if not m:
        return [Finding("hsts", HIGH, "Strict-Transport-Security has no valid max-age",
                        f"Value: {v}", "Use: max-age=31536000; includeSubDomains")]
    age = int(m.group(1))
    if age == 0:
        out.append(Finding("hsts", HIGH, "HSTS disabled (max-age=0)",
                           "max-age=0 tells browsers to forget the HSTS policy.",
                           "Set max-age to at least 31536000 (1 year)."))
    elif age < SIX_MONTHS:
        out.append(Finding("hsts", MEDIUM, f"HSTS max-age too short ({age}s = {_days(age)})",
                           "Short lifetimes leave a wide window for downgrade attacks.",
                           "Set max-age to at least 31536000 (1 year)."))
    elif age < ONE_YEAR:
        out.append(Finding("hsts", LOW, f"HSTS max-age below 1 year ({_days(age)})",
                           "Recommended minimum is one year (also required for preload).",
                           "Set max-age=31536000 or higher."))
    else:
        out.append(Finding("hsts", PASS, f"HSTS max-age {_days(age)}"))
    if "includesubdomains" not in directives:
        out.append(Finding("hsts", LOW, "HSTS without includeSubDomains",
                           "Sub-domains can still be reached over HTTP and used to set cookies for the parent domain.",
                           "Add includeSubDomains once every sub-domain supports HTTPS."))
    if "preload" in directives:
        out.append(Finding("hsts", PASS, "HSTS preload requested"))
    return out


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a CSP into {directive: [sources]}. Multiple policies are merged."""
    policy: dict[str, list[str]] = {}
    for part in re.split(r"[;,]", value):
        tokens = part.strip().split()
        if tokens:
            name = tokens[0].lower()
            policy.setdefault(name, []).extend(t.lower() for t in tokens[1:])
    return policy


def check_csp(h: Headers) -> list[Finding]:
    v = h.get("Content-Security-Policy")
    ro = h.get("Content-Security-Policy-Report-Only")
    if not v:
        if ro:
            return [Finding("csp", MEDIUM, "CSP is report-only (not enforced)",
                            "Content-Security-Policy-Report-Only only reports violations; it blocks nothing.",
                            "Once reports are clean, send the same policy as Content-Security-Policy.")]
        return [Finding("csp", HIGH, "Content-Security-Policy missing",
                        "CSP is the main browser defence against cross-site scripting (XSS) and data injection.",
                        "Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; "
                        "base-uri 'self'; frame-ancestors 'self'  and loosen only where needed.")]
    p = parse_csp(v)
    out: list[Finding] = []
    script = p.get("script-src", p.get("default-src"))
    if script is None:
        out.append(Finding("csp", MEDIUM, "CSP has no script-src or default-src",
                           "Scripts can be loaded from anywhere, so the policy does not stop XSS.",
                           "Add default-src 'self' (and a script-src if you need more sources)."))
    else:
        has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script)
        if "'unsafe-inline'" in script and not has_nonce_or_hash:
            out.append(Finding("csp", MEDIUM, "CSP allows 'unsafe-inline' scripts",
                               "Inline scripts are allowed, which removes most of CSP's XSS protection.",
                               "Remove 'unsafe-inline'; use nonces ('nonce-...') or hashes for inline scripts."))
        if "'unsafe-eval'" in script:
            out.append(Finding("csp", MEDIUM, "CSP allows 'unsafe-eval'",
                               "eval() and similar let injected strings run as code.",
                               "Remove 'unsafe-eval' and refactor code that uses eval / new Function."))
        loose = [s for s in script if s in ("*", "http:", "https:", "data:")]
        if loose:
            out.append(Finding("csp", MEDIUM, f"CSP script sources too broad: {' '.join(loose)}",
                               "Attackers can load scripts from any host matching these sources.",
                               "List the specific hosts you load scripts from, or use 'self' + nonces."))
        if not any(f.severity != PASS for f in out):
            out.append(Finding("csp", PASS, "CSP restricts script sources"))
    obj = p.get("object-src", p.get("default-src"))
    if obj is None or obj != ["'none'"] and "'none'" not in obj:
        out.append(Finding("csp", LOW, "CSP object-src not 'none'",
                           "Plugins (<object>/<embed>) can be used to bypass script restrictions.",
                           "Add object-src 'none'."))
    if "base-uri" not in p:
        out.append(Finding("csp", LOW, "CSP base-uri not set",
                           "An injected <base> tag can redirect relative script URLs to an attacker's host.",
                           "Add base-uri 'self' (or 'none')."))
    return out


def check_framing(h: Headers) -> list[Finding]:
    csp = parse_csp(h.get("Content-Security-Policy") or "")
    if "frame-ancestors" in csp:
        fa = csp["frame-ancestors"]
        if "*" in fa:
            return [Finding("framing", MEDIUM, "CSP frame-ancestors allows any site (*)",
                            "Any site can frame this page, enabling clickjacking.",
                            "Use frame-ancestors 'self' (or 'none').")]
        return [Finding("framing", PASS, "Clickjacking protection via CSP frame-ancestors")]
    xfo = h.get("X-Frame-Options")
    if not xfo:
        return [Finding("framing", MEDIUM, "No clickjacking protection",
                        "Neither X-Frame-Options nor CSP frame-ancestors is set; other sites can frame this page.",
                        "Add X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'.")]
    val = xfo.strip().upper()
    if val in ("DENY", "SAMEORIGIN"):
        return [Finding("framing", PASS, f"X-Frame-Options: {val}")]
    if val.startswith("ALLOW-FROM"):
        return [Finding("framing", MEDIUM, "X-Frame-Options ALLOW-FROM is not supported by modern browsers",
                        "Browsers ignore ALLOW-FROM, so the page is effectively frameable.",
                        "Use CSP frame-ancestors <allowed-origin> instead.")]
    return [Finding("framing", MEDIUM, f"Invalid X-Frame-Options value: {xfo}",
                    "Browsers ignore invalid values.", "Use DENY or SAMEORIGIN.")]


def check_nosniff(h: Headers) -> list[Finding]:
    v = h.get("X-Content-Type-Options")
    if v and v.strip().lower() == "nosniff":
        return [Finding("nosniff", PASS, "X-Content-Type-Options: nosniff")]
    return [Finding("nosniff", MEDIUM,
                    "X-Content-Type-Options missing" if not v else f"Invalid X-Content-Type-Options: {v}",
                    "Browsers may MIME-sniff responses and run uploaded files as scripts or HTML.",
                    "Add: X-Content-Type-Options: nosniff")]


SAFE_REFERRER = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
WEAK_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}


def check_referrer(h: Headers) -> list[Finding]:
    v = h.get("Referrer-Policy")
    if not v:
        return [Finding("referrer", LOW, "Referrer-Policy missing",
                        "Browsers fall back to their own default; older ones leak full URLs (with tokens/IDs) to other sites.",
                        "Add: Referrer-Policy: strict-origin-when-cross-origin")]
    # Browsers use the last value they understand
    vals = [x.strip().lower() for x in v.split(",") if x.strip()]
    effective = vals[-1] if vals else ""
    if effective in WEAK_REFERRER:
        return [Finding("referrer", MEDIUM, f"Weak Referrer-Policy: {effective}",
                        "Full URLs, including paths and query strings, are sent to other sites.",
                        "Use strict-origin-when-cross-origin or no-referrer.")]
    if effective in SAFE_REFERRER:
        return [Finding("referrer", PASS, f"Referrer-Policy: {effective}")]
    return [Finding("referrer", INFO, f"Referrer-Policy: {effective}",
                    "Valid but leaks more than recommended (origin sent to all sites).",
                    "Consider strict-origin-when-cross-origin.")]


def check_permissions(h: Headers) -> list[Finding]:
    if h.get("Permissions-Policy"):
        return [Finding("permissions", PASS, "Permissions-Policy set")]
    if h.get("Feature-Policy"):
        return [Finding("permissions", LOW, "Only deprecated Feature-Policy set",
                        "Feature-Policy was replaced by Permissions-Policy.",
                        "Add Permissions-Policy, e.g. camera=(), microphone=(), geolocation=()")]
    return [Finding("permissions", LOW, "Permissions-Policy missing",
                    "Embedded or injected content can request powerful features (camera, mic, location).",
                    "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()")]


def check_cross_origin(h: Headers) -> list[Finding]:
    out = []
    for name, good, why in (
        ("Cross-Origin-Opener-Policy", ("same-origin", "same-origin-allow-popups"),
         "isolates the window from cross-origin pages it opens (helps against XS-Leaks / Spectre)"),
        ("Cross-Origin-Resource-Policy", ("same-origin", "same-site"),
         "stops other sites embedding this resource"),
    ):
        v = h.get(name)
        if v and v.strip().lower() in good:
            out.append(Finding("cross-origin", PASS, f"{name}: {v.strip()}"))
        else:
            out.append(Finding("cross-origin", INFO, f"{name} not set" if not v else f"{name}: {v}",
                               f"Optional hardening: {why}.",
                               f"Consider {name}: {good[0]}"))
    return out


DISCLOSURE_HEADERS = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
                      "X-Generator", "X-Drupal-Cache", "X-Runtime"]


def check_disclosure(h: Headers) -> list[Finding]:
    out = []
    server = h.get("Server")
    if server and re.search(r"\d", server):
        out.append(Finding("disclosure", LOW, f"Server version disclosed: {server}",
                           "Exact versions help attackers match known CVEs.",
                           "Hide the version (nginx: server_tokens off; Apache: ServerTokens Prod)."))
    for name in DISCLOSURE_HEADERS:
        v = h.get(name)
        if v:
            out.append(Finding("disclosure", LOW, f"{name} disclosed: {v}",
                               "Reveals the technology stack and version.",
                               f"Remove the {name} header."))
    if not out:
        out.append(Finding("disclosure", PASS, "No technology/version disclosure"))
    return out


def check_cors(h: Headers) -> list[Finding]:
    acao = h.get("Access-Control-Allow-Origin")
    if not acao:
        return []
    creds = (h.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
    a = acao.strip()
    if a == "*" and creds:
        return [Finding("cors", HIGH, "CORS: wildcard origin with credentials",
                        "A misconfiguration: credentials with '*' signals the server may be reflecting trust broadly.",
                        "Allow only specific trusted origins, never '*' with credentials.")]
    if a == "null":
        return [Finding("cors", MEDIUM, "CORS allows the 'null' origin",
                        "Sandboxed iframes and local files send Origin: null, so attackers can use it.",
                        "Never allow 'null'; list explicit origins.")]
    if a == "*":
        return [Finding("cors", LOW, "CORS allows any origin (*)",
                        "Fine for public, unauthenticated APIs/assets; risky for anything user-specific.",
                        "Restrict to known origins unless the content is fully public.")]
    return [Finding("cors", PASS, f"CORS restricted to {a}")]


def check_deprecated(h: Headers) -> list[Finding]:
    out = []
    xxss = h.get("X-XSS-Protection")
    if xxss and xxss.strip() != "0":
        out.append(Finding("deprecated", INFO, f"X-XSS-Protection: {xxss}",
                           "The legacy XSS auditor is removed from modern browsers and could itself be abused.",
                           "Set X-XSS-Protection: 0 (or remove it) and rely on CSP."))
    for name in ("Expect-CT", "Public-Key-Pins"):
        if h.get(name):
            out.append(Finding("deprecated", INFO, f"Deprecated header {name} present",
                               "No longer supported by browsers.", f"Remove {name}."))
    return out


SESSIONISH = re.compile(r"sess|sid|auth|token|login|jwt|remember", re.I)


def parse_cookie(raw: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        if not p:
            continue
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name, attrs


def check_cookies(h: Headers, url: str) -> list[Finding]:
    https = urlparse(url).scheme == "https"
    out = []
    for raw in h.getlist("Set-Cookie"):
        name, a = parse_cookie(raw)
        problems = []
        sev = LOW
        sensitive = bool(SESSIONISH.search(name))
        if "secure" not in a:
            problems.append("no Secure flag (sent over HTTP)")
            if https or sensitive:
                sev = MEDIUM
        if "httponly" not in a:
            problems.append("no HttpOnly flag (readable by JavaScript / XSS)")
            if sensitive:
                sev = MEDIUM
        samesite = a.get("samesite", "").lower()
        if not samesite:
            problems.append("no SameSite attribute (CSRF exposure)")
        elif samesite == "none" and "secure" not in a:
            problems.append("SameSite=None without Secure (rejected by browsers)")
            sev = MEDIUM
        if name.startswith("__Host-") and ("secure" not in a or "domain" in a or a.get("path") != "/"):
            problems.append("__Host- prefix rules broken (needs Secure, Path=/, no Domain)")
            sev = MEDIUM
        if name.startswith("__Secure-") and "secure" not in a:
            problems.append("__Secure- prefix requires Secure")
            sev = MEDIUM
        if problems:
            detail = ("Name suggests a session/auth cookie, so weak flags matter more."
                      if sensitive else "Missing cookie protections.")
            out.append(Finding("cookies", sev, f"Cookie '{name}': " + "; ".join(problems), detail,
                               f"Set-Cookie: {name}=...; Secure; HttpOnly; SameSite=Lax; Path=/"))
        else:
            out.append(Finding("cookies", PASS, f"Cookie '{name}' has Secure, HttpOnly, SameSite"))
    return out


def analyze(headers: Headers, url: str, http_redirects_to_https: bool | None = None) -> list[Finding]:
    findings: list[Finding] = []
    findings += check_https(url, http_redirects_to_https)
    findings += check_hsts(headers, url)
    findings += check_csp(headers)
    findings += check_framing(headers)
    findings += check_nosniff(headers)
    findings += check_referrer(headers)
    findings += check_permissions(headers)
    findings += check_cross_origin(headers)
    findings += check_cookies(headers, url)
    findings += check_cors(headers)
    findings += check_disclosure(headers)
    findings += check_deprecated(headers)
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return findings


# =========================================================================== #
# Fetching
# =========================================================================== #

def normalize_url(target: str) -> str:
    target = target.strip()
    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target
    p = urlparse(target)
    if not p.hostname:
        raise ValueError(f"Invalid URL: {target}")
    return target


def _session(insecure: bool, no_proxy: bool):
    import requests
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    s.verify = not insecure
    if no_proxy:
        s.trust_env = False
    return s


def _final_headers(resp) -> Headers:
    raw = getattr(resp.raw, "headers", None)
    if raw is not None and hasattr(raw, "items"):
        return Headers(raw.items())          # urllib3 keeps duplicate Set-Cookie
    return Headers(resp.headers.items())


def fetch(url: str, timeout: float = 10, insecure: bool = False, no_proxy: bool = False,
          check_redirect: bool = True) -> Report:
    import requests
    s = _session(insecure, no_proxy)
    try:
        if insecure:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        resp = s.get(url, timeout=timeout, allow_redirects=True, stream=True)
        resp.close()
    except requests.exceptions.SSLError as e:
        return Report(url, url, None, error=f"TLS/certificate error: {_short(e)} (use --insecure to skip verification)")
    except requests.exceptions.RequestException as e:
        return Report(url, url, None, error=f"Request failed: {_short(e)}")

    headers = _final_headers(resp)
    redirects = [r.url for r in resp.history]
    final = resp.url

    http_to_https = None
    if check_redirect and urlparse(final).scheme == "https":
        p = urlparse(url)
        http_url = "http://" + p.netloc + (p.path or "/")
        try:
            r2 = s.get(http_url, timeout=timeout, allow_redirects=True, stream=True)
            r2.close()
            http_to_https = urlparse(r2.url).scheme == "https"
        except requests.exceptions.RequestException:
            http_to_https = None  # port 80 closed / unreachable: don't penalise

    rep = Report(url, final, resp.status_code, redirects, headers=headers.as_dict())
    rep.findings = analyze(headers, final, http_to_https)
    return rep


def _short(e: Exception) -> str:
    s = str(e)
    return s if len(s) < 160 else s[:157] + "..."


def parse_raw_headers(text: str) -> Headers:
    """Parse saved headers such as the output of `curl -sI`."""
    pairs = []
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line or line.upper().startswith("HTTP/") or ":" not in line:
            continue
        k, _, v = line.partition(":")
        if k.strip() and " " not in k.strip():
            pairs.append((k, v))
    return Headers(pairs)


# =========================================================================== #
# Output
# =========================================================================== #

class Color:
    def __init__(self, on: bool):
        c = (lambda code: (lambda s: f"\033[{code}m{s}\033[0m")) if on else (lambda code: (lambda s: s))
        self.red, self.yellow, self.blue, self.green = c("31"), c("33"), c("36"), c("32")
        self.dim, self.bold, self.mag = c("2"), c("1"), c("35")


def grade_color(col: Color, g: str):
    return {"A+": col.green, "A": col.green, "B": col.blue, "C": col.yellow,
            "D": col.mag, "F": col.red}.get(g, col.red)


def render_text(rep: Report, col: Color, show_pass: bool = True) -> str:
    L = []
    L.append(col.bold("=" * 72))
    L.append(col.bold(f" {rep.url}"))
    if rep.error:
        L.append(col.red(f" [ERROR] {rep.error}"))
        return "\n".join(L)
    if rep.redirects:
        L.append(col.dim(f" -> final URL: {rep.final_url}  ({len(rep.redirects)} redirect(s))"))
    gc = grade_color(col, rep.grade)
    c = rep.counts()
    status = f"HTTP {rep.status}" if rep.status is not None else "offline analysis"
    L.append(f" Grade: {gc(col.bold(rep.grade))}   Score: {rep.score}/100   {status}")
    L.append(f" {col.red(str(c[HIGH]) + ' high')}  {col.yellow(str(c[MEDIUM]) + ' medium')}  "
             f"{col.blue(str(c[LOW]) + ' low')}  {col.dim(str(c[INFO]) + ' info')}  "
             f"{col.green(str(c[PASS]) + ' passed')}")
    L.append(col.bold("-" * 72))
    tag = {HIGH: col.red("[HIGH]  "), MEDIUM: col.yellow("[MEDIUM]"), LOW: col.blue("[LOW]   "),
           INFO: col.dim("[INFO]  "), PASS: col.green("[PASS]  ")}
    for f in rep.findings:
        if f.severity == PASS and not show_pass:
            continue
        L.append(f" {tag[f.severity]} {f.title}")
        if f.severity != PASS:
            if f.detail:
                L.append(col.dim(f"            why: {f.detail}"))
            if f.fix:
                L.append(f"            fix: {f.fix}")
    return "\n".join(L)


def write_json(reports: list[Report], path: str):
    data = {"tool": f"HeaderScan {__version__}", "results": [r.to_dict() for r in reports]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def write_csv(reports: list[Report], path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "final_url", "grade", "score", "check", "severity", "title", "fix"])
        for r in reports:
            if r.error:
                w.writerow([r.url, r.final_url, r.grade, "", "", "error", r.error, ""])
            for fd in r.findings:
                w.writerow([r.url, r.final_url, r.grade, r.score, fd.check, fd.severity, fd.title, fd.fix])


def summary_table(reports: list[Report], col: Color) -> str:
    L = [col.bold("\nSUMMARY"), f" {'Grade':<6}{'Score':>6}  {'High':>4} {'Med':>4} {'Low':>4}  URL"]
    for r in reports:
        if r.error:
            L.append(f" {col.red('ERR'):<6}{'-':>6}  {'-':>4} {'-':>4} {'-':>4}  {r.url}")
            continue
        c = r.counts()
        g = grade_color(col, r.grade)(f"{r.grade:<6}")
        L.append(f" {g}{r.score:>6}  {c[HIGH]:>4} {c[MEDIUM]:>4} {c[LOW]:>4}  {r.url}")
    return "\n".join(L)


# =========================================================================== #
# CLI
# =========================================================================== #

def _finish(reports: list[Report], args) -> int:
    col = Color(sys.stdout.isatty() and not args.no_color)
    for r in reports:
        print(render_text(r, col, show_pass=not args.issues_only))
    if len(reports) > 1:
        print(summary_table(reports, col))
    if args.json:
        write_json(reports, args.json)
        print(f"\n[+] JSON report written to {args.json}")
    if args.csv:
        write_csv(reports, args.csv)
        print(f"[+] CSV report written to {args.csv}")
    if any(r.error for r in reports):
        return 2
    if args.min_grade and any(GRADE_RANK[r.grade] > GRADE_RANK[args.min_grade] for r in reports):
        print(f"\n[-] One or more sites graded below {args.min_grade}.", file=sys.stderr)
        return 1
    return 0


def cmd_scan(args) -> int:
    targets = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            targets += [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    if not targets:
        print("[-] No URLs given.", file=sys.stderr)
        return 2
    reports = []
    for t in targets:
        try:
            url = normalize_url(t)
        except ValueError as e:
            reports.append(Report(t, t, None, error=str(e)))
            continue
        reports.append(fetch(url, timeout=args.timeout, insecure=args.insecure,
                             no_proxy=args.no_proxy, check_redirect=not args.no_redirect_check))
    return _finish(reports, args)


def cmd_analyze(args) -> int:
    reports = []
    for path in args.files:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                h = parse_raw_headers(f.read())
        except OSError as e:
            reports.append(Report(path, path, None, error=str(e)))
            continue
        url = args.url or "https://offline-analysis"
        rep = Report(path, url, None, headers=h.as_dict())
        rep.findings = analyze(h, url)
        reports.append(rep)
    return _finish(reports, args)


# =========================================================================== #
# Built-in test suite   ->   python headerscan.py selftest
# =========================================================================== #
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GOOD = [
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
    ("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; "
                                "base-uri 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Server", "nginx"),
    ("Set-Cookie", "__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
]


def _sev(findings, check):
    return [f.severity for f in findings if f.check == check]


class GradingTests(unittest.TestCase):
    def test_good_site_gets_a_plus(self):
        r = Report("u", "https://x", 200)
        r.findings = analyze(Headers(GOOD), "https://x", True)
        self.assertEqual(r.grade, "A+", [f.title for f in r.findings if f.severity != PASS])

    def test_empty_headers_get_f(self):
        r = Report("u", "https://x", 200)
        r.findings = analyze(Headers([]), "https://x", False)
        self.assertEqual(r.grade, "F")

    def test_http_site_flagged(self):
        f = analyze(Headers(GOOD), "http://x")
        self.assertIn(HIGH, _sev(f, "https"))
        self.assertEqual(_sev(f, "hsts"), [])  # HSTS not judged over HTTP

    def test_score_never_negative(self):
        r = Report("u", "http://x", 200)
        r.findings = [Finding("x", HIGH, "t")] * 10
        self.assertEqual(r.score, 0)


class HSTSTests(unittest.TestCase):
    def sev(self, v):
        return _sev(check_hsts(Headers([("Strict-Transport-Security", v)]), "https://x"), "hsts")

    def test_missing(self):
        self.assertEqual(_sev(check_hsts(Headers([]), "https://x"), "hsts"), [HIGH])

    def test_zero(self):
        self.assertIn(HIGH, self.sev("max-age=0"))

    def test_short(self):
        self.assertIn(MEDIUM, self.sev("max-age=3600; includeSubDomains"))

    def test_under_year(self):
        self.assertIn(LOW, self.sev("max-age=20000000; includeSubDomains"))

    def test_no_subdomains(self):
        self.assertIn(LOW, self.sev("max-age=31536000"))

    def test_good(self):
        self.assertEqual(set(self.sev("max-age=31536000; includeSubDomains")), {PASS})


class CSPTests(unittest.TestCase):
    def sev(self, v):
        return [f.severity for f in check_csp(Headers([("Content-Security-Policy", v)]))]

    def test_missing(self):
        self.assertEqual(_sev(check_csp(Headers([])), "csp"), [HIGH])

    def test_report_only(self):
        f = check_csp(Headers([("Content-Security-Policy-Report-Only", "default-src 'self'")]))
        self.assertEqual(f[0].severity, MEDIUM)

    def test_unsafe_inline(self):
        self.assertIn(MEDIUM, self.sev("default-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"))

    def test_unsafe_inline_with_nonce_ok(self):
        self.assertNotIn(MEDIUM, self.sev("script-src 'self' 'unsafe-inline' 'nonce-x'; object-src 'none'; base-uri 'none'"))

    def test_unsafe_eval(self):
        self.assertIn(MEDIUM, self.sev("script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'none'"))

    def test_wildcard(self):
        self.assertIn(MEDIUM, self.sev("script-src *; object-src 'none'; base-uri 'none'"))

    def test_no_script_or_default(self):
        self.assertIn(MEDIUM, self.sev("img-src 'self'"))

    def test_object_src_and_base_uri(self):
        self.assertEqual(self.sev("default-src 'self'").count(LOW), 2)

    def test_strict_policy(self):
        self.assertEqual(set(self.sev("default-src 'none'; script-src 'self'; base-uri 'none'")), {PASS})


class OtherHeaderTests(unittest.TestCase):
    def test_framing(self):
        self.assertEqual(check_framing(Headers([]))[0].severity, MEDIUM)
        self.assertEqual(check_framing(Headers([("X-Frame-Options", "sameorigin")]))[0].severity, PASS)
        self.assertEqual(check_framing(Headers([("X-Frame-Options", "ALLOW-FROM https://a")]))[0].severity, MEDIUM)
        self.assertEqual(check_framing(Headers([("Content-Security-Policy", "frame-ancestors 'self'")]))[0].severity, PASS)
        self.assertEqual(check_framing(Headers([("Content-Security-Policy", "frame-ancestors *")]))[0].severity, MEDIUM)

    def test_nosniff(self):
        self.assertEqual(check_nosniff(Headers([("X-Content-Type-Options", "nosniff")]))[0].severity, PASS)
        self.assertEqual(check_nosniff(Headers([("X-Content-Type-Options", "yes")]))[0].severity, MEDIUM)

    def test_referrer(self):
        self.assertEqual(check_referrer(Headers([]))[0].severity, LOW)
        self.assertEqual(check_referrer(Headers([("Referrer-Policy", "unsafe-url")]))[0].severity, MEDIUM)
        self.assertEqual(check_referrer(Headers([("Referrer-Policy", "unsafe-url, no-referrer")]))[0].severity, PASS)

    def test_permissions(self):
        self.assertEqual(check_permissions(Headers([("Feature-Policy", "camera 'none'")]))[0].severity, LOW)

    def test_disclosure(self):
        f = check_disclosure(Headers([("Server", "Apache/2.4.29 (Ubuntu)"), ("X-Powered-By", "PHP/7.2.24")]))
        self.assertEqual([x.severity for x in f], [LOW, LOW])
        self.assertEqual(check_disclosure(Headers([("Server", "cloudflare")]))[0].severity, PASS)

    def test_cors(self):
        self.assertEqual(check_cors(Headers([("Access-Control-Allow-Origin", "*"),
                                             ("Access-Control-Allow-Credentials", "true")]))[0].severity, HIGH)
        self.assertEqual(check_cors(Headers([("Access-Control-Allow-Origin", "null")]))[0].severity, MEDIUM)
        self.assertEqual(check_cors(Headers([("Access-Control-Allow-Origin", "*")]))[0].severity, LOW)
        self.assertEqual(check_cors(Headers([])), [])

    def test_deprecated(self):
        self.assertEqual(len(check_deprecated(Headers([("X-XSS-Protection", "1; mode=block"),
                                                       ("Expect-CT", "max-age=0")]))), 2)
        self.assertEqual(check_deprecated(Headers([("X-XSS-Protection", "0")])), [])


class CookieTests(unittest.TestCase):
    def one(self, cookie, url="https://x"):
        return check_cookies(Headers([("Set-Cookie", cookie)]), url)[0]

    def test_secure_cookie_passes(self):
        self.assertEqual(self.one("id=1; Secure; HttpOnly; SameSite=Strict").severity, PASS)

    def test_session_cookie_without_flags_is_medium(self):
        f = self.one("PHPSESSID=abc; path=/")
        self.assertEqual(f.severity, MEDIUM)
        self.assertIn("HttpOnly", f.title)
        self.assertIn("SameSite", f.title)

    def test_samesite_none_without_secure(self):
        self.assertEqual(self.one("pref=1; HttpOnly; SameSite=None").severity, MEDIUM)

    def test_host_prefix_rules(self):
        self.assertIn("__Host-", self.one("__Host-x=1; Secure; HttpOnly; SameSite=Lax; Domain=a.com; Path=/").title)

    def test_multiple_cookies(self):
        h = Headers([("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Lax"), ("Set-Cookie", "b=2")])
        self.assertEqual([f.severity for f in check_cookies(h, "https://x")], [PASS, MEDIUM])


class ParsingTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")
        self.assertEqual(normalize_url("http://a.b/c"), "http://a.b/c")
        with self.assertRaises(ValueError):
            normalize_url("https://")

    def test_curl_output(self):
        raw = ("HTTP/2 200\r\nserver: nginx/1.18.0\r\nset-cookie: a=1\r\nset-cookie: b=2\r\n"
               "x-frame-options: DENY\r\n\r\n")
        h = parse_raw_headers(raw)
        self.assertEqual(h.getlist("Set-Cookie"), ["a=1", "b=2"])
        self.assertEqual(h.get("X-FRAME-OPTIONS"), "DENY")

    def test_csp_parse(self):
        p = parse_csp("default-src 'self'; script-src 'self' https://cdn.x; ")
        self.assertEqual(p["script-src"], ["'self'", "https://cdn.x"])


class _Handler(BaseHTTPRequestHandler):
    routes: dict = {}

    def do_GET(self):
        status, headers = self.routes.get(self.path, (404, []))
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class LiveServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        port = cls.srv.server_address[1]
        cls.base = f"http://127.0.0.1:{port}"
        _Handler.routes = {
            "/old": (301, [("Location", "/bad")]),
            "/bad": (200, [("Server", "Apache/2.4.29 (Ubuntu)"), ("X-Powered-By", "PHP/7.2.24"),
                           ("Set-Cookie", "PHPSESSID=abc; path=/"), ("Set-Cookie", "theme=dark")]),
        }
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_fetch_follows_redirect_and_grades(self):
        r = fetch(self.base + "/old", timeout=5, no_proxy=True)
        self.assertIsNone(r.error)
        self.assertEqual(r.final_url, self.base + "/bad")
        self.assertEqual(len(r.redirects), 1)
        self.assertEqual(r.grade, "F")
        titles = " | ".join(f.title for f in r.findings)
        self.assertIn("not served over HTTPS", titles)
        self.assertIn("PHP/7.2.24", titles)
        self.assertIn("PHPSESSID", titles)
        self.assertIn("theme", titles)  # both Set-Cookie headers kept

    def test_unreachable_host(self):
        r = fetch("http://127.0.0.1:9/", timeout=2, no_proxy=True)
        self.assertIsNotNone(r.error)
        self.assertEqual(r.grade, "ERR")

    def test_json_and_csv_export(self):
        import os
        import tempfile
        r = fetch(self.base + "/bad", timeout=5, no_proxy=True)
        with tempfile.TemporaryDirectory() as d:
            jp, cp = os.path.join(d, "r.json"), os.path.join(d, "r.csv")
            write_json([r], jp)
            write_csv([r], cp)
            data = json.load(open(jp))
            self.assertEqual(data["results"][0]["grade"], "F")
            rows = list(csv.reader(open(cp)))
            self.assertEqual(rows[0][:3], ["url", "final_url", "grade"])
            self.assertEqual(len(rows) - 1, len(r.findings))


def cmd_selftest(args) -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for case in (GradingTests, HSTSTests, CSPTests, OtherHeaderTests, CookieTests,
                 ParsingTests, LiveServerTests):
        suite.addTests(loader.loadTestsFromTestCase(case))
    result = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    return 0 if result.wasSuccessful() else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="headerscan",
                                description="Check a website's HTTP security headers and grade them A+ to F.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def out_opts(sp):
        sp.add_argument("--json", metavar="PATH", help="write a JSON report")
        sp.add_argument("--csv", metavar="PATH", help="write a CSV report (one row per finding)")
        sp.add_argument("--issues-only", action="store_true", help="hide passed checks")
        sp.add_argument("--no-color", action="store_true", help="disable colours")
        sp.add_argument("--min-grade", choices=[g for _, g in GRADES],
                        help="exit with code 1 if any site grades below this (for CI)")

    s = sub.add_parser("scan", help="fetch and grade one or more websites")
    s.add_argument("urls", nargs="*", help="URLs or domains (https:// assumed)")
    s.add_argument("-f", "--file", help="file with one URL per line (# for comments)")
    s.add_argument("--timeout", type=float, default=10, help="seconds per request (default 10)")
    s.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    s.add_argument("--no-proxy", action="store_true", help="ignore HTTP(S)_PROXY environment variables")
    s.add_argument("--no-redirect-check", action="store_true", help="don't test the http:// -> https:// redirect")
    out_opts(s)
    s.set_defaults(func=cmd_scan)

    a = sub.add_parser("analyze", help="grade saved headers (e.g. output of `curl -sI`) offline")
    a.add_argument("files", nargs="+")
    a.add_argument("--url", help="URL the headers came from (default assumes HTTPS)")
    out_opts(a)
    a.set_defaults(func=cmd_analyze)

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
