#!/usr/bin/env python3
"""
==============================================================================
 IRGen - Cybersecurity Incident Report Generator   (single-file project)
==============================================================================
This one file is the complete project:
  * the tool        turn incident notes + tool output into a professional report
  * the docs        this header
  * the test suite  python irgen.py selftest

Requirements: Python 3.9+   (standard library only, nothing to install)
------------------------------------------------------------------------------

WHAT IT DOES
  You describe an incident in a simple JSON file (what happened, when, what
  was affected, what you did). IRGen validates it, enriches it and writes a
  report that follows the NIST SP 800-61 incident-handling structure:

    1. Executive summary          (written automatically from the facts)
    2. Incident details           (category, source, handler, status, TLP)
    3. Key metrics                (time to detect / contain / resolve)
    4. Timeline                   (sorted, gaps and order checked)
    5. Affected assets & impact   (confidentiality / integrity / availability)
    6. Data involved & notification duties (GDPR 72-hour window, PCI DSS)
    7. Evidence & findings        (imported from security tools)
    8. Indicators of compromise   (auto-extracted and DEFANGED: 203.0.113[.]7)
    9. MITRE ATT&CK mapping       (listed + suggested techniques with tactics)
   10. Response actions           (containment, eradication, recovery)
   11. Root cause, recommendations, lessons learned
   12. Sign-off

  Enrichment
    * Severity is calculated from impact, data involved and evidence, and
      you are warned if the declared severity looks too low.
    * Indicators (IPs, URLs, domains, hashes, emails) are pulled out of the
      timeline and summary automatically, de-duplicated and defanged so the
      report can be shared safely.
    * ATT&CK techniques are suggested from keywords (phishing -> T1566 ...).
    * Recommendations are generated from the evidence (leaked secret ->
      rotate it and add pre-commit scanning, missing HSTS -> enable HSTS ...).

  Imports (--import, repeatable)
    * LeakHunter JSON     (project 13)
    * HeaderScan JSON     (project 11)
    * SARIF 2.1.0         (GitHub code scanning, Semgrep, many scanners)
    * Generic CSV / JSON  (columns/keys: severity, title, asset, detail)

  Outputs
    * HTML  - self-contained, print-ready (File > Print > Save as PDF)
    * Markdown - for GitHub, wikis, tickets
    * JSON  - normalised, enriched data for other tools

USAGE
  python irgen.py template -o incident.json        # sample incident to edit
  python irgen.py validate incident.json
  python irgen.py generate incident.json -o report.html -o report.md
  python irgen.py generate incident.json --import leakhunter.json \\
                  --import headerscan.json -o report.html
  python irgen.py selftest -v

  Exit codes: 0 ok, 1 validation errors, 2 bad input file.

INCIDENT FILE (key fields; run `template` for a full example)
  id, title, organization, classification (TLP:CLEAR|GREEN|AMBER|AMBER+STRICT|RED),
  status (Open|Contained|Eradicated|Recovered|Closed), severity (optional),
  category, detection_source, reported_by, handler,
  dates {first_activity, detected, contained, resolved}   ISO 8601
  summary, affected_assets [{name, type, impact}],
  data_involved {pii, records, types[]},
  impact {confidentiality, integrity, availability}  none|low|medium|high
  timeline [{time, event, actor}], iocs [{type, value, note}],
  attack_techniques ["T1552.001", ...],
  actions {containment[], eradication[], recovery[]},
  root_cause, recommendations[], lessons_learned[], evidence[], evidence_files[]

LIMITATIONS
  * The report is only as good as the facts entered. IRGen checks structure
    and consistency, not whether the facts are true.
  * ATT&CK suggestions come from keywords; confirm them before publishing.
  * Notification notes are reminders, not legal advice. Check the laws that
    apply to you with your legal / privacy team.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

__version__ = "1.0.0"

SEVERITIES = ["low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
IMPACT_LEVELS = ["none", "low", "medium", "high"]
STATUSES = ["Open", "Contained", "Eradicated", "Recovered", "Closed"]
TLP = {
    "TLP:CLEAR": ("#ffffff", "Disclosure is not limited."),
    "TLP:GREEN": ("#33ff00", "Limited disclosure, restricted to the community."),
    "TLP:AMBER": ("#ffc000", "Limited disclosure, restricted to participants' organisations."),
    "TLP:AMBER+STRICT": ("#ffc000", "Restricted to the recipient's organisation only."),
    "TLP:RED": ("#ff2b2b", "For the eyes and ears of individual recipients only."),
}

# A small, accurate subset of MITRE ATT&CK Enterprise: id -> (name, tactic)
ATTACK = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1133": ("External Remote Services", "Initial Access"),
    "T1566": ("Phishing", "Initial Access"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Phishing: Spearphishing Link", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access / Persistence"),
    "T1078.004": ("Valid Accounts: Cloud Accounts", "Initial Access / Persistence"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence"),
    "T1547.001": ("Boot or Logon Autostart: Registry Run Keys / Startup Folder", "Persistence"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1136": ("Create Account", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1530": ("Data from Cloud Storage", "Collection"),
    "T1213": ("Data from Information Repositories", "Collection"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1567.002": ("Exfiltration Over Web Service: Exfiltration to Cloud Storage", "Exfiltration"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
}

ATTACK_KEYWORDS = [
    (r"spear-?phish\w*.*attach|malicious attachment|macro", "T1566.001"),
    (r"phishing link|malicious link|credential harvest", "T1566.002"),
    (r"phish", "T1566"),
    (r"password spray", "T1110.003"),
    (r"brute.?force|failed login|credential stuffing", "T1110"),
    (r"(?:leak|exposed|hard.?coded|committed|pushed).{0,40}(?:key|secret|credential|password|token)"
     r"|(?:key|secret|credential|token).{0,40}(?:leak|exposed|committed|pushed|public repo)", "T1552.001"),
    (r"aws|azure|gcp|cloud (?:account|console|api)|iam (?:user|key)", "T1078.004"),
    (r"valid (?:account|credential)|stolen credential|compromised account", "T1078"),
    (r"s3 bucket|blob storage|cloud storage|listobjects|getobject", "T1530"),
    (r"\bexploit(?:ed|ing)?\b.{0,40}(?:server|application|app|vulnerab|cve)|cve-\d{4}-\d+|sql injection|\brce\b|remote code execution", "T1190"),
    (r"web ?shell", "T1505.003"),
    (r"powershell", "T1059.001"),
    (r"cmd\.exe|command shell", "T1059.003"),
    (r"scheduled task|schtasks", "T1053.005"),
    (r"run key|startup folder", "T1547.001"),
    (r"mimikatz|lsass|credential dump", "T1003"),
    (r"\brdp\b|remote desktop", "T1021.001"),
    (r"\bvpn\b|external remote", "T1133"),
    (r"port scan|nmap|network scan", "T1046"),
    (r"ransom|encrypted files|files encrypted", "T1486"),
    (r"shadow cop|vssadmin|backup deleted", "T1490"),
    (r"exfiltrat\w* (?:over|via|through) (?:the )?(?:c2|command.and.control|beacon)", "T1041"),
    (r"exfiltrat\w* (?:to|via) (?:dropbox|google drive|onedrive|mega|cloud storage|s3)", "T1567.002"),
    (r"dns tunnel", "T1071.004"),
    (r"event log(?:s)? (?:cleared|deleted)|wevtutil", "T1070.001"),
    (r"new (?:admin |user )?account (?:was )?created|created (?:a )?(?:new )?(?:admin )?(?:user|account)|\bcreateuser\b|net user /add", "T1136"),
]


# =========================================================================== #
# Data model
# =========================================================================== #

@dataclass
class Evidence:
    source: str
    severity: str
    title: str
    asset: str = ""
    detail: str = ""
    recommendation: str = ""


@dataclass
class IOC:
    type: str
    value: str
    note: str = ""
    auto: bool = False

    @property
    def defanged(self) -> str:
        return defang(self.type, self.value)


@dataclass
class Incident:
    raw: dict
    evidence: list[Evidence] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    techniques: list[tuple[str, str, str, bool]] = field(default_factory=list)  # id, name, tactic, suggested
    severity: str = "medium"
    severity_reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    dates: dict[str, datetime | None] = field(default_factory=dict)
    timeline: list[dict] = field(default_factory=list)

    def t(self, text) -> str:
        """Free text, defanged for safe sharing."""
        return defang_text(text, tuple(i.value for i in self.iocs if i.type == "domain"))

    def get(self, key, default=""):
        v = self.raw.get(key, default)
        return default if v is None else v


class InputError(Exception):
    pass


# =========================================================================== #
# Helpers
# =========================================================================== #

def parse_time(value) -> datetime | None:
    if value in (None, ""):
        return None
    s = str(value).strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Unrecognised date/time: {value!r} (use ISO 8601, e.g. 2026-11-03T14:20:00Z)")


def fmt_time(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "-"


def human_duration(td: timedelta | None) -> str:
    if td is None:
        return "-"
    mins = int(td.total_seconds() // 60)
    if mins < 0:
        return "negative (check dates)"
    d, rem = divmod(mins, 1440)
    h, m = divmod(rem, 60)
    parts = [f"{d}d" if d else "", f"{h}h" if h else "", f"{m}m" if m or not (d or h) else ""]
    return " ".join(p for p in parts if p)


def defang(kind: str, value: str) -> str:
    v = value
    if kind in ("url", "domain", "ip", "email"):
        v = re.sub(r"^http", "hxxp", v, flags=re.I)
        v = v.replace("://", "[://]") if kind == "url" else v
        v = v.replace("@", "[@]")
        # bracket the last dot of the host part only (keeps paths readable)
        host_match = re.match(r"^(hxxps?\[://\])?([^/]+)", v)
        if host_match:
            host = host_match.group(2)
            i = host.rfind(".")
            if i > 0:
                new_host = host[:i] + "[.]" + host[i + 1:]
                v = v[:host_match.start(2)] + new_host + v[host_match.end(2):]
    return v


_TEXT_IOC = re.compile(r"\bhttps?://[^\s\"'<>()]+|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|"
                       r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", re.I)


def defang_text(text: str, extra_domains: tuple[str, ...] = ()) -> str:
    """Defang every URL, email and IP (plus listed IOC domains) inside free text."""
    def sub(m):
        v = m.group(0)
        kind = "url" if v.lower().startswith("http") else "email" if "@" in v else "ip"
        if kind == "url":
            v = v.rstrip(".,;:")
            return defang(kind, v) + m.group(0)[len(v):]
        return defang(kind, v)
    out = _TEXT_IOC.sub(sub, str(text))
    for d in extra_domains:
        out = re.sub(r"(?<![\w.\[])" + re.escape(d) + r"(?![\w])", defang("domain", d), out, flags=re.I)
    return out


def norm_sev(value: str, default: str = "medium") -> str:
    v = str(value or "").strip().lower()
    aliases = {"error": "high", "warning": "medium", "note": "low", "info": "low", "informational": "low",
               "moderate": "medium", "severe": "high", "crit": "critical"}
    v = aliases.get(v, v)
    return v if v in SEV_RANK else default


# =========================================================================== #
# IOC extraction
# =========================================================================== #

IOC_PATTERNS = [
    ("url", re.compile(r"\bhttps?://[^\s\"'<>()]+", re.I)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("ip", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]
PRIVATE_IP = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|169\.254\.)")


def extract_iocs(text: str) -> list[IOC]:
    found: list[IOC] = []
    taken: list[tuple[int, int]] = []
    for kind, pat in IOC_PATTERNS:
        for m in pat.finditer(text):
            if any(s < m.end() and m.start() < e for s, e in taken):
                continue
            value = m.group(0).rstrip(".,;:")
            note = "internal address" if kind == "ip" and PRIVATE_IP.match(value) else ""
            found.append(IOC(kind, value, note, auto=True))
            taken.append(m.span())
    return found


def merge_iocs(manual: list[IOC], auto: list[IOC]) -> list[IOC]:
    seen = {(i.type, i.value.lower()) for i in manual}
    out = list(manual)
    for i in auto:
        key = (i.type, i.value.lower())
        if key not in seen:
            seen.add(key)
            out.append(i)
    order = ["ip", "domain", "url", "email", "sha256", "sha1", "md5"]
    return sorted(out, key=lambda i: (order.index(i.type) if i.type in order else 99, i.value))


# =========================================================================== #
# Importers
# =========================================================================== #

def import_file(path: str) -> list[Evidence]:
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise InputError(f"Cannot read {path}: {e.strerror}")
    name = os.path.basename(path)
    if path.lower().endswith(".csv"):
        return _import_csv(text, name)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise InputError(f"{path} is not valid JSON or CSV: {e}")
    tool = str(data.get("tool", "")) if isinstance(data, dict) else ""
    if tool.startswith("LeakHunter"):
        return _import_leakhunter(data)
    if tool.startswith("HeaderScan"):
        return _import_headerscan(data)
    if isinstance(data, dict) and "runs" in data and str(data.get("version", "")).startswith("2."):
        return _import_sarif(data)
    if isinstance(data, list):
        return [_generic(item, name) for item in data if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [_generic(item, name) for item in data["findings"] if isinstance(item, dict)]
    raise InputError(f"{path}: unrecognised format (expected LeakHunter, HeaderScan, SARIF, CSV or a list)")


LEAK_RECS = {
    "secret": "Revoke and rotate the exposed credential, then remove it from code and git history.",
    "pii": "Remove personal data from the repository/file share and assess notification duties.",
}


def _import_leakhunter(data) -> list[Evidence]:
    out = []
    for f in data.get("findings", []):
        out.append(Evidence("LeakHunter", norm_sev(f.get("severity")),
                            f"{f.get('rule', 'Leak')} exposed",
                            f"{f.get('file', '')}:{f.get('line', '')}",
                            f"Masked value: {f.get('masked', '')}",
                            LEAK_RECS.get(f.get("category", ""), "")))
    return out


def _import_headerscan(data) -> list[Evidence]:
    out = []
    for r in data.get("results", []):
        url = r.get("final_url") or r.get("url", "")
        if r.get("error"):
            out.append(Evidence("HeaderScan", "low", "Site could not be scanned", url, r["error"]))
            continue
        for f in r.get("findings", []):
            if f.get("severity") in ("pass", "info"):
                continue
            out.append(Evidence("HeaderScan", norm_sev(f.get("severity")), f.get("title", ""), url,
                                f.get("detail", ""), f.get("fix", "")))
    return out


def _import_sarif(data) -> list[Evidence]:
    out = []
    for run in data.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "SARIF")
        for res in run.get("results", []):
            loc = ""
            try:
                pl = res["locations"][0]["physicalLocation"]
                loc = f"{pl['artifactLocation']['uri']}:{pl.get('region', {}).get('startLine', '')}"
            except (KeyError, IndexError, TypeError):
                pass
            out.append(Evidence(tool, norm_sev(res.get("level"), "medium"),
                                res.get("message", {}).get("text", res.get("ruleId", "")), loc,
                                f"Rule: {res.get('ruleId', '')}"))
    return out


def _generic(item: dict, source: str) -> Evidence:
    return Evidence(str(item.get("source", source)), norm_sev(item.get("severity")),
                    str(item.get("title") or item.get("name") or item.get("finding") or "Finding"),
                    str(item.get("asset") or item.get("host") or item.get("file") or ""),
                    str(item.get("detail") or item.get("description") or ""),
                    str(item.get("recommendation") or item.get("fix") or ""))


def _import_csv(text: str, name: str) -> list[Evidence]:
    rows = list(csv.DictReader(text.splitlines()))
    return [_generic({k.strip().lower(): v for k, v in r.items() if k}, name) for r in rows]


# =========================================================================== #
# Validation & enrichment
# =========================================================================== #

REQUIRED = ["id", "title", "organization", "category", "summary", "dates"]


def build(raw: dict, imports: list[str] | None = None, base_dir: str = ".") -> tuple[Incident, list[str]]:
    """Validate and enrich. Returns (incident, errors)."""
    inc = Incident(raw)
    errors: list[str] = []

    for k in REQUIRED:
        if not raw.get(k):
            errors.append(f"Missing required field: {k}")

    cls = str(raw.get("classification", "TLP:AMBER")).upper()
    if cls not in TLP:
        errors.append(f"classification must be one of {', '.join(TLP)}")
    raw["classification"] = cls if cls in TLP else "TLP:AMBER"

    status = str(raw.get("status", "Open")).title()
    if status not in STATUSES:
        errors.append(f"status must be one of {', '.join(STATUSES)}")
    raw["status"] = status

    # ---- dates & metrics ----
    d = raw.get("dates") or {}
    for key in ("first_activity", "detected", "contained", "resolved"):
        try:
            inc.dates[key] = parse_time(d.get(key))
        except ValueError as e:
            errors.append(f"dates.{key}: {e}")
            inc.dates[key] = None
    if raw.get("dates") and not inc.dates.get("detected"):
        errors.append("dates.detected is required")
    order = [k for k in ("first_activity", "detected", "contained", "resolved") if inc.dates.get(k)]
    for a, b in zip(order, order[1:]):
        if inc.dates[b] < inc.dates[a]:
            errors.append(f"dates.{b} ({fmt_time(inc.dates[b])}) is before dates.{a} ({fmt_time(inc.dates[a])})")
    if status in ("Recovered", "Closed") and not inc.dates.get("resolved"):
        inc.warnings.append(f"Status is {status} but dates.resolved is empty.")
    if status in ("Contained", "Eradicated", "Recovered", "Closed") and not inc.dates.get("contained"):
        inc.warnings.append(f"Status is {status} but dates.contained is empty.")

    # ---- timeline ----
    for i, ev in enumerate(raw.get("timeline") or []):
        try:
            t = parse_time(ev.get("time"))
        except ValueError as e:
            errors.append(f"timeline[{i}]: {e}")
            continue
        if not ev.get("event"):
            errors.append(f"timeline[{i}]: missing event text")
            continue
        inc.timeline.append({"time": t, "event": str(ev["event"]), "actor": str(ev.get("actor", ""))})
    inc.timeline.sort(key=lambda e: e["time"])
    if inc.timeline and inc.dates.get("detected") and inc.dates.get("first_activity") is None:
        inc.dates["first_activity"] = inc.timeline[0]["time"]
        inc.warnings.append("dates.first_activity not given; using the first timeline event.")

    # ---- impact ----
    impact = raw.get("impact") or {}
    for k in ("confidentiality", "integrity", "availability"):
        v = str(impact.get(k, "none")).lower()
        if v not in IMPACT_LEVELS:
            errors.append(f"impact.{k} must be one of {', '.join(IMPACT_LEVELS)}")
            v = "none"
        impact[k] = v
    raw["impact"] = impact

    # ---- evidence ----
    for e in raw.get("evidence") or []:
        if isinstance(e, dict):
            inc.evidence.append(_generic(e, "Analyst"))
    for path in list(raw.get("evidence_files") or []) + list(imports or []):
        full = path if os.path.isabs(path) or path in (imports or []) else os.path.join(base_dir, path)
        try:
            inc.evidence += import_file(full)
        except InputError as e:
            errors.append(str(e))
    inc.evidence.sort(key=lambda e: -SEV_RANK[e.severity])

    # ---- IOCs ----
    manual = []
    for i in raw.get("iocs") or []:
        if isinstance(i, dict) and i.get("value"):
            manual.append(IOC(str(i.get("type", "other")).lower(), str(i["value"]), str(i.get("note", ""))))
    text = " ".join([str(raw.get("summary", ""))] + [e["event"] for e in inc.timeline])
    inc.iocs = merge_iocs(manual, extract_iocs(text))

    # ---- ATT&CK ----
    listed = [str(t).upper() for t in raw.get("attack_techniques") or []]
    for tid in listed:
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
            errors.append(f"attack_techniques: {tid!r} is not a valid technique id (e.g. T1566 or T1566.001)")
            continue
        name, tactic = ATTACK.get(tid, ("(not in built-in table; check attack.mitre.org)", "-"))
        inc.techniques.append((tid, name, tactic, False))
    corpus = " ".join([str(raw.get("category", "")), str(raw.get("summary", "")), str(raw.get("root_cause", ""))]
                      + [e["event"] for e in inc.timeline] + [e.title for e in inc.evidence]).lower()
    have = {t[0] for t in inc.techniques}
    for pattern, tid in ATTACK_KEYWORDS:
        parent = tid.split(".")[0]
        if tid in have or any(h.startswith(tid + ".") for h in have) or (tid == parent and any(
                h.startswith(parent) for h in have)):
            continue
        if re.search(pattern, corpus):
            inc.techniques.append((tid, *ATTACK[tid], True))
            have.add(tid)
    tactic_order = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Defense Evasion",
                    "Credential Access", "Discovery", "Lateral Movement", "Collection",
                    "Command and Control", "Exfiltration", "Impact"]
    inc.techniques.sort(key=lambda t: next((i for i, x in enumerate(tactic_order) if t[2].startswith(x)), 99))

    # ---- severity ----
    computed, reasons = compute_severity(raw, inc.evidence)
    declared = norm_sev(raw.get("severity"), "") if raw.get("severity") else ""
    if raw.get("severity") and not declared:
        errors.append(f"severity must be one of {', '.join(SEVERITIES)}")
    if declared:
        inc.severity = declared
        inc.severity_reasons = ["declared by incident handler"]
        if SEV_RANK[computed] > SEV_RANK[declared]:
            inc.warnings.append(f"Declared severity '{declared}' is lower than the facts suggest "
                                f"('{computed}': {'; '.join(reasons)}).")
    else:
        inc.severity, inc.severity_reasons = computed, reasons

    inc.recommendations = build_recommendations(raw, inc)
    return inc, errors


def compute_severity(raw: dict, evidence: list[Evidence]) -> tuple[str, list[str]]:
    reasons = []
    impact = raw.get("impact") or {}
    levels = [IMPACT_LEVELS.index(impact.get(k, "none")) for k in ("confidentiality", "integrity", "availability")]
    sev = max(0, max(levels) - 1) if levels else 0   # none/low->low, medium->medium, high->high
    if max(levels or [0]) >= 2:
        worst = [k for k in ("confidentiality", "integrity", "availability") if
                 IMPACT_LEVELS.index(impact.get(k, "none")) == max(levels)]
        reasons.append(f"{IMPACT_LEVELS[max(levels)]} impact on {', '.join(worst)}")
    if levels.count(3) >= 2:
        sev = 3
        reasons.append("high impact on two or more of C/I/A")
    di = raw.get("data_involved") or {}
    if di.get("pii"):
        records = int(di.get("records") or 0)
        if sev < 2:
            sev = 2
        reasons.append(f"personal data involved ({records} records)" if records else "personal data involved")
        if records >= 10000:
            sev = 3
            reasons.append("10,000+ records")
    if evidence:
        top = max(SEV_RANK[e.severity] for e in evidence)
        if top >= 3 and sev < 2:
            sev = 2
            reasons.append("critical findings in evidence")
    if not reasons:
        reasons.append("limited impact")
    return SEVERITIES[sev], reasons


# (when the incident text matches, what an existing tool recommendation must match to count as covered, advice)
REC_RULES = [
    (r"leak|exposed|credential|secret|key|token|password", r"rotat|revoke",
     "Rotate every exposed credential and review its usage logs for the full exposure window."),
    (r"leak|exposed|secret|key|token", r"secret scanning|pre-commit|secrets manager",
     "Add secret scanning to pre-commit hooks and CI (e.g. LeakHunter --fail-on high) and use a secrets manager."),
    (r"aws|cloud|s3|iam", r"least.privilege|iam polic",
     "Enforce least-privilege IAM policies, enable MFA on all cloud accounts and alert on unusual API calls."),
    (r"phish", r"phishing|mail gateway",
     "Run targeted phishing-awareness training and block the sender domains/URLs at the mail gateway."),
    (r"brute|password spray|failed login", r"\bmfa\b|lockout|rate limit",
     "Enforce MFA and account lockout / rate limiting on all login endpoints."),
    (r"strict-transport-security|hsts", r"strict-transport|hsts",
     "Enable HSTS (max-age=31536000; includeSubDomains) on all HTTPS sites."),
    (r"content-security-policy|\bcsp\b", r"content-security-policy|\bcsp\b",
     "Deploy a Content-Security-Policy without 'unsafe-inline'."),
    (r"cookie", r"cookie|httponly|samesite", "Set Secure, HttpOnly and SameSite on all session cookies."),
    (r"ransom|encrypt", r"backup", "Keep offline, immutable backups and test restores regularly."),
    (r"malware|trojan|backdoor|web ?shell", r"reimage", 
     "Reimage affected hosts from known-good images rather than cleaning them in place."),
    (r"exploit|cve-|vulnerab|unpatched", r"patch", "Patch the exploited software and add it to the vulnerability-scanning scope."),
]


def build_recommendations(raw: dict, inc: Incident) -> list[str]:
    recs = [str(r) for r in raw.get("recommendations") or []]
    corpus = " ".join([str(raw.get("category", "")), str(raw.get("summary", "")), str(raw.get("root_cause", ""))]
                      + [e.title for e in inc.evidence] + [e["event"] for e in inc.timeline]).lower()
    auto = []
    for pattern, _, text in REC_RULES:
        if re.search(pattern, corpus) and text not in auto:
            auto.append(text)
    di = raw.get("data_involved") or {}
    if di.get("pii"):
        auto.append("Review data retention: delete or tokenise personal data that does not need to be stored.")
    for e in inc.evidence:
        rec = e.recommendation
        if not rec or SEV_RANK[e.severity] < 2 or rec in auto:
            continue
        # skip tool advice that a broader recommendation above already covers
        covered = any(t in auto and re.search(c, rec.lower()) for _, c, t in REC_RULES)
        if covered or (di.get("pii") and "personal data" in rec.lower()):
            continue
        auto.append(rec)
    if not inc.dates.get("first_activity") or not inc.timeline:
        auto.append("Improve logging and retention so the full attack timeline can be reconstructed.")
    lower = {r.lower() for r in recs}
    return recs + [a + "  (auto)" for a in auto if a.lower() not in lower][:10]


def notification_notes(raw: dict, inc: Incident) -> list[str]:
    di = raw.get("data_involved") or {}
    notes = []
    if not di.get("pii"):
        return notes
    det = inc.dates.get("detected")
    if det:
        notes.append(f"GDPR (if EU/UK personal data): notify the supervisory authority within 72 hours of becoming "
                     f"aware, where the breach is likely to risk people's rights. Window ends {fmt_time(det + timedelta(hours=72))}.")
    types = " ".join(str(t).lower() for t in di.get("types") or [])
    if re.search(r"card|pan|payment", types):
        notes.append("PCI DSS: payment card data involved; inform your acquiring bank / card brands per your incident response plan.")
    if re.search(r"ssn|social security|health|medical", types):
        notes.append("US state breach-notification laws and sector rules (e.g. HIPAA for health data) may apply; deadlines vary by state.")
    notes.append("Confirm all notification duties with your legal / privacy team (this is a checklist, not legal advice).")
    return notes


def metrics(inc: Incident) -> list[tuple[str, str]]:
    d = inc.dates
    def diff(a, b):
        return d[b] - d[a] if d.get(a) and d.get(b) else None
    return [("Time to detect", human_duration(diff("first_activity", "detected"))),
            ("Time to contain", human_duration(diff("detected", "contained"))),
            ("Time to resolve", human_duration(diff("detected", "resolved"))),
            ("Total duration", human_duration(diff("first_activity", "resolved")))]


def executive_summary(inc: Incident) -> str:
    r = inc.raw
    det = inc.dates.get("detected")
    s = (f"On {det.strftime('%d %B %Y') if det else 'an unknown date'}, {r.get('organization', 'the organisation')} "
         f"detected a security incident ({str(r.get('category', 'unclassified')).lower()})"
         f"{' via ' + r['detection_source'] if r.get('detection_source') else ''}. "
         f"{str(r.get('summary', '')).strip()} ")
    s += f"The incident is rated {inc.severity.upper()} ({'; '.join(inc.severity_reasons)}). "
    assets = r.get("affected_assets") or []
    if assets:
        s += f"{len(assets)} asset{'s were' if len(assets) != 1 else ' was'} affected. "
    di = r.get("data_involved") or {}
    if di.get("pii") and not any("personal data" in x for x in inc.severity_reasons):
        s += f"Personal data was involved{' (' + str(di.get('records')) + ' records)' if di.get('records') else ''}. "
    m = dict(metrics(inc))
    if inc.dates.get("contained"):
        s += f"It was contained {m['Time to contain']} after detection"
        s += f" and resolved after {m['Time to resolve']}. " if inc.dates.get("resolved") else ". "
    s += f"Current status: {r.get('status', 'Open')}."
    return inc.t(re.sub(r"\s+", " ", s).strip())


# =========================================================================== #
# Renderers
# =========================================================================== #

def md_escape(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_markdown(inc: Incident) -> str:
    r = inc.raw
    L = [f"# Incident Report: {r.get('title', '')}", ""]
    L.append(f"**{r['classification']}** · **Incident ID:** {r.get('id', '')} · **Severity:** {inc.severity.upper()} · "
             f"**Status:** {r['status']}  ")
    L.append(f"**Organisation:** {r.get('organization', '')} · **Report generated:** "
             f"{fmt_time(datetime.now(timezone.utc))} by IRGen {__version__}")
    L += ["", "## 1. Executive summary", "", executive_summary(inc), ""]
    if inc.warnings:
        L += ["> **Review notes**", ">"] + [f"> - {w}" for w in inc.warnings] + [""]
    L += ["## 2. Incident details", "", "| Field | Value |", "|---|---|"]
    for k, label in (("category", "Category"), ("detection_source", "Detection source"),
                     ("reported_by", "Reported by"), ("handler", "Incident handler")):
        L.append(f"| {label} | {md_escape(r.get(k, '-') or '-')} |")
    for k in ("first_activity", "detected", "contained", "resolved"):
        L.append(f"| {k.replace('_', ' ').capitalize()} | {fmt_time(inc.dates.get(k))} |")
    L += ["", "## 3. Key metrics", "", "| Metric | Value |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in metrics(inc)]
    L += ["", "## 4. Timeline", "", "| Time (UTC) | Event | Actor |", "|---|---|---|"]
    L += [f"| {fmt_time(e['time'])} | {md_escape(inc.t(e['event']))} | {md_escape(e['actor'] or '-')} |" for e in inc.timeline]
    L += ["", "## 5. Affected assets and impact", ""]
    assets = r.get("affected_assets") or []
    if assets:
        L += ["| Asset | Type | Impact |", "|---|---|---|"]
        L += [f"| {md_escape(a.get('name', ''))} | {md_escape(a.get('type', ''))} | {md_escape(a.get('impact', ''))} |"
              for a in assets]
    imp = r["impact"]
    L += ["", f"**Confidentiality:** {imp['confidentiality']} · **Integrity:** {imp['integrity']} · "
              f"**Availability:** {imp['availability']}", ""]
    di = r.get("data_involved") or {}
    L += ["## 6. Data involved and notification", ""]
    if di.get("pii"):
        L.append(f"Personal data: **yes** · Records: **{di.get('records', 'unknown')}** · "
                 f"Types: {', '.join(di.get('types') or []) or '-'}")
        L += [""] + [f"- {n}" for n in notification_notes(r, inc)]
    else:
        L.append("No personal data reported as involved.")
    L += ["", f"## 7. Evidence and findings ({len(inc.evidence)})", ""]
    if inc.evidence:
        L += ["| Severity | Finding | Asset | Source |", "|---|---|---|---|"]
        L += [f"| {e.severity.upper()} | {md_escape(inc.t(e.title))} | {md_escape(e.asset)} | {md_escape(e.source)} |"
              for e in inc.evidence]
    else:
        L.append("No evidence attached.")
    L += ["", f"## 8. Indicators of compromise ({len(inc.iocs)})", "",
          "_Defanged for safe sharing. `[.]` = `.`, `hxxp` = `http`._", ""]
    if inc.iocs:
        L += ["| Type | Indicator | Note |", "|---|---|---|"]
        L += [f"| {i.type} | `{i.defanged}` | {md_escape(i.note)}{' (auto-extracted)' if i.auto else ''} |"
              for i in inc.iocs]
    L += ["", "## 9. MITRE ATT&CK mapping", ""]
    if inc.techniques:
        L += ["| Tactic | Technique | Source |", "|---|---|---|"]
        L += [f"| {t[2]} | {t[0]} {md_escape(t[1])} | {'suggested - confirm' if t[3] else 'analyst'} |"
              for t in inc.techniques]
    acts = r.get("actions") or {}
    L += ["", "## 10. Response actions", ""]
    for phase in ("containment", "eradication", "recovery"):
        L.append(f"**{phase.capitalize()}**")
        L += [f"- {inc.t(a)}" for a in acts.get(phase) or ["(none recorded)"]] + [""]
    L += ["## 11. Root cause", "", inc.t(r.get("root_cause") or "Not yet determined."), "",
          "## 12. Recommendations", ""]
    L += [f"{n}. {inc.t(x.replace('  (auto)', ''))}{' _(auto)_' if x.endswith('(auto)') else ''}"
          for n, x in enumerate(inc.recommendations, 1)]
    L += ["", "## 13. Lessons learned", ""]
    L += [f"- {inc.t(x)}" for x in r.get("lessons_learned") or ["To be completed in the post-incident review."]]
    L += ["", "## 14. Sign-off", "", "| Role | Name | Date |", "|---|---|---|",
          f"| Incident handler | {md_escape(r.get('handler', ''))} | |", "| Security manager | | |", ""]
    return "\n".join(L)


CSS = """
*{box-sizing:border-box}body{margin:0;background:#eef1f5;font:15px/1.55 -apple-system,"Segoe UI",Roboto,
"DejaVu Sans",Arial,sans-serif;color:#1f2933}.page{max-width:960px;margin:28px auto;background:#fff;
box-shadow:0 2px 16px rgba(0,0,0,.08);border-radius:10px;overflow:hidden}.tlp{background:#000;padding:8px 40px;
font:700 14px/1 "DejaVu Sans Mono",monospace;letter-spacing:1px;display:flex;justify-content:space-between}
.tlp small{color:#aaa;font-weight:400;letter-spacing:0}header{padding:34px 40px 26px;background:#0f1b2d;color:#fff}
header .kicker{font-size:12px;letter-spacing:2px;color:#8fa3bf;text-transform:uppercase}
header h1{margin:6px 0 14px;font-size:30px;line-height:1.2}.meta{display:flex;flex-wrap:wrap;gap:8px 22px;
font-size:13.5px;color:#c9d4e3}.meta b{color:#fff}.badge{display:inline-block;padding:3px 10px;border-radius:999px;
font-size:12px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:#fff}
.critical{background:#8b1e3f}.high{background:#c0392b}.medium{background:#d68910}.low{background:#2874a6}
main{padding:10px 40px 36px}h2{font-size:18px;margin:30px 0 10px;padding-bottom:6px;border-bottom:2px solid #e4e8ee;
color:#0f1b2d}h2 span{color:#8fa3bf;font-weight:400;margin-right:6px}table{width:100%;border-collapse:collapse;
font-size:13.5px;margin:6px 0}th{text-align:left;background:#f4f6f9;color:#52606d;font-weight:600;padding:8px 10px;
border-bottom:1px solid #dde2e8}td{padding:8px 10px;border-bottom:1px solid #eef1f4;vertical-align:top}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:8px 0}.card{border:1px solid #e4e8ee;
border-radius:8px;padding:12px 14px}.card .v{font-size:20px;font-weight:700;color:#0f1b2d}.card .k{font-size:12px;
color:#7b8794;text-transform:uppercase;letter-spacing:.5px}.summary{background:#f7f9fc;border-left:4px solid #0f1b2d;
padding:14px 18px;border-radius:4px}.warn{background:#fff8e6;border-left:4px solid #d68910;padding:10px 16px;
border-radius:4px;font-size:13.5px;margin-top:12px}.warn ul{margin:4px 0 0;padding-left:18px}code{font:12.5px
"DejaVu Sans Mono",monospace;background:#f4f6f9;padding:1px 5px;border-radius:3px;overflow-wrap:anywhere}
td.asset{width:28%}td.sev{width:1%;white-space:nowrap}
.cia{display:flex;gap:10px;margin-top:10px}.cia div{flex:1;border:1px solid #e4e8ee;border-radius:8px;padding:10px 14px;
font-size:13px}.cia b{display:block;font-size:16px;text-transform:capitalize}.lvl-high b{color:#c0392b}
.lvl-medium b{color:#d68910}.lvl-low b{color:#2874a6}.lvl-none b{color:#7b8794}.muted{color:#7b8794}
.tag{font-size:11px;padding:1px 7px;border-radius:999px;background:#eef1f5;color:#52606d;white-space:nowrap}
.phase{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.phase div{border:1px solid #e4e8ee;
border-radius:8px;padding:10px 14px}.phase h3{margin:0 0 4px;font-size:14px}.phase ul{margin:0;padding-left:18px;
font-size:13.5px}ol li,ul li{margin:3px 0}footer{padding:14px 40px;font-size:12px;color:#7b8794;border-top:1px solid #e4e8ee}
@media print{body{background:#fff}.page{box-shadow:none;margin:0;max-width:none;border-radius:0}h2{break-after:avoid}
tr{break-inside:avoid}}
"""


def render_html(inc: Incident) -> str:
    e = html.escape
    r = inc.raw
    color, tlp_desc = TLP[r["classification"]]
    sev = inc.severity

    def table(head, rows):
        return ("<table><tr>" + "".join(f"<th>{h}</th>" for h in head) + "</tr>" +
                "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows) + "</table>")

    def section(n, title, body):
        return f"<h2><span>{n}.</span>{e(title)}</h2>{body}"

    out = [f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>{e(r.get('id', ''))} - "
           f"{e(r.get('title', ''))}</title><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<style>{CSS}</style></head><body><div class='page'>"]
    out.append(f"<div class='tlp' style='color:{color}'>{e(r['classification'])}<small>{e(tlp_desc)}</small></div>")
    out.append(f"<header><div class='kicker'>Incident Report · {e(r.get('organization', ''))}</div>"
               f"<h1>{e(r.get('title', ''))}</h1><div class='meta'>"
               f"<span><b>ID</b> {e(r.get('id', ''))}</span>"
               f"<span><b>Severity</b> <span class='badge {sev}'>{sev}</span></span>"
               f"<span><b>Status</b> {e(r['status'])}</span>"
               f"<span><b>Handler</b> {e(r.get('handler', '-') or '-')}</span>"
               f"<span><b>Detected</b> {fmt_time(inc.dates.get('detected'))}</span></div></header><main>")

    body = f"<div class='summary'>{e(executive_summary(inc))}</div>"
    if inc.warnings:
        body += "<div class='warn'><b>Review notes</b><ul>" + "".join(f"<li>{e(w)}</li>" for w in inc.warnings) + "</ul></div>"
    out.append(section(1, "Executive summary", body))

    rows = [[label, e(str(r.get(k) or "-"))] for k, label in
            (("category", "Category"), ("detection_source", "Detection source"),
             ("reported_by", "Reported by"), ("handler", "Incident handler"))]
    rows += [[k.replace("_", " ").capitalize(), fmt_time(inc.dates.get(k))]
             for k in ("first_activity", "detected", "contained", "resolved")]
    out.append(section(2, "Incident details", table(["Field", "Value"], rows)))

    cards = "".join(f"<div class='card'><div class='k'>{e(k)}</div><div class='v'>{e(v)}</div></div>"
                    for k, v in metrics(inc))
    out.append(section(3, "Key metrics", f"<div class='cards'>{cards}</div>"))

    out.append(section(4, "Timeline", table(["Time (UTC)", "Event", "Actor"],
               [[f"<span style='white-space:nowrap'>{fmt_time(t['time'])}</span>", e(inc.t(t["event"])),
                 e(t["actor"] or "-")] for t in inc.timeline]) if inc.timeline else "<p class='muted'>No timeline recorded.</p>"))

    assets = r.get("affected_assets") or []
    body = table(["Asset", "Type", "Impact"], [[e(str(a.get("name", ""))), e(str(a.get("type", ""))),
                                                e(str(a.get("impact", "")))] for a in assets]) if assets else ""
    imp = r["impact"]
    body += "<div class='cia'>" + "".join(f"<div class='lvl-{imp[k]}'>{k.capitalize()}<b>{imp[k]}</b></div>"
                                          for k in ("confidentiality", "integrity", "availability")) + "</div>"
    out.append(section(5, "Affected assets and impact", body))

    di = r.get("data_involved") or {}
    if di.get("pii"):
        body = (f"<p>Personal data: <b>yes</b> · Records: <b>{e(str(di.get('records', 'unknown')))}</b> · "
                f"Types: {e(', '.join(map(str, di.get('types') or [])) or '-')}</p><ul>" +
                "".join(f"<li>{e(n)}</li>" for n in notification_notes(r, inc)) + "</ul>")
    else:
        body = "<p class='muted'>No personal data reported as involved.</p>"
    out.append(section(6, "Data involved and notification", body))

    body = table(["Severity", "Finding", "Asset", "Source"],
                 [[f"<span class='badge {x.severity}'>{x.severity}</span>",
                   e(inc.t(x.title)) + (f"<div class='muted'>{e(inc.t(x.detail))}</div>" if x.detail else ""),
                   (f"<code>{e(x.asset).replace('/', '/<wbr>')}</code>" if x.asset else "-"), e(x.source)] for x in inc.evidence]) \
        if inc.evidence else "<p class='muted'>No evidence attached.</p>"
    out.append(section(7, f"Evidence and findings ({len(inc.evidence)})", body))

    body = ("<p class='muted'>Defanged for safe sharing: <code>[.]</code> = <code>.</code>, "
            "<code>hxxp</code> = <code>http</code>.</p>" +
            table(["Type", "Indicator", "Note"], [[e(i.type), f"<code>{e(i.defanged)}</code>",
                  e(i.note) + (" <span class='tag'>auto-extracted</span>" if i.auto else "")] for i in inc.iocs])) \
        if inc.iocs else "<p class='muted'>No indicators recorded.</p>"
    out.append(section(8, f"Indicators of compromise ({len(inc.iocs)})", body))

    body = table(["Tactic", "Technique", "Source"],
                 [[e(t[2]), f"<b>{e(t[0])}</b> {e(t[1])}",
                   "<span class='tag'>suggested - confirm</span>" if t[3] else "analyst"] for t in inc.techniques]) \
        if inc.techniques else "<p class='muted'>No techniques mapped.</p>"
    out.append(section(9, "MITRE ATT&CK mapping", body))

    acts = r.get("actions") or {}
    body = "<div class='phase'>" + "".join(
        f"<div><h3>{p.capitalize()}</h3><ul>" + "".join(f"<li>{e(inc.t(a))}</li>" for a in acts.get(p) or []) +
        ("" if acts.get(p) else "<li class='muted'>None recorded</li>") + "</ul></div>"
        for p in ("containment", "eradication", "recovery")) + "</div>"
    out.append(section(10, "Response actions", body))
    out.append(section(11, "Root cause", f"<p>{e(inc.t(r.get('root_cause') or 'Not yet determined.'))}</p>"))
    out.append(section(12, "Recommendations", "<ol>" + "".join(
        f"<li>{e(inc.t(x.replace('  (auto)', '')))}{' <span class=tag>auto</span>' if x.endswith('(auto)') else ''}</li>"
        for x in inc.recommendations) + "</ol>"))
    out.append(section(13, "Lessons learned", "<ul>" + "".join(
        f"<li>{e(inc.t(x))}</li>" for x in r.get("lessons_learned") or ["To be completed in the post-incident review."]) + "</ul>"))
    out.append(section(14, "Sign-off", table(["Role", "Name", "Signature / date"],
               [["Incident handler", e(str(r.get("handler", ""))), ""], ["Security manager", "", ""]])))
    out.append(f"</main><footer>{e(r['classification'])} · {e(r.get('id', ''))} · Generated "
               f"{fmt_time(datetime.now(timezone.utc))} by IRGen {__version__} · Structure follows NIST SP 800-61</footer>"
               "</div></body></html>")
    return "".join(out)


def render_json(inc: Incident) -> str:
    def ser(v):
        if isinstance(v, datetime):
            return v.isoformat()
        raise TypeError
    data = {
        "generator": f"IRGen {__version__}",
        "incident": {k: v for k, v in inc.raw.items() if k not in ("evidence", "iocs", "timeline")},
        "severity": inc.severity, "severity_reasons": inc.severity_reasons,
        "executive_summary": executive_summary(inc),
        "metrics": dict(metrics(inc)),
        "timeline": inc.timeline,
        "evidence": [asdict(x) for x in inc.evidence],
        "iocs": [{**asdict(i), "defanged": i.defanged} for i in inc.iocs],
        "attack": [{"id": t[0], "name": t[1], "tactic": t[2], "suggested": t[3]} for t in inc.techniques],
        "recommendations": inc.recommendations,
        "notification": notification_notes(inc.raw, inc),
        "warnings": inc.warnings,
    }
    return json.dumps(data, indent=2, default=ser)


# =========================================================================== #
# Sample incident (used by `template` and the tests)
# =========================================================================== #

SAMPLE = {
    "id": "IR-2026-0042",
    "title": "AWS access key leaked in public GitHub repository",
    "organization": "Acme Corp",
    "classification": "TLP:AMBER",
    "status": "Closed",
    "category": "Unauthorized access / credential leak",
    "detection_source": "AWS GuardDuty alert",
    "reported_by": "Cloud Operations on-call",
    "handler": "J. Rivera (SOC)",
    "dates": {
        "first_activity": "2026-11-02T21:14:00Z",
        "detected": "2026-11-03T08:05:00Z",
        "contained": "2026-11-03T09:40:00Z",
        "resolved": "2026-11-05T17:30:00Z",
    },
    "summary": ("A developer pushed a configuration file containing a production AWS access key to a public "
                "GitHub repository. An unknown actor used the key to list and download objects from the "
                "customer-exports S3 bucket, including a CSV file with customer contact and payment data."),
    "affected_assets": [
        {"name": "acme-webapp (GitHub)", "type": "Source code repository", "impact": "Secrets exposed publicly"},
        {"name": "svc-deploy (IAM user)", "type": "Cloud identity", "impact": "Access key abused"},
        {"name": "s3://acme-customer-exports", "type": "Cloud storage", "impact": "2 objects downloaded"},
    ],
    "data_involved": {"pii": True, "records": 2, "types": ["names", "emails", "phone numbers", "card numbers", "SSNs"]},
    "impact": {"confidentiality": "high", "integrity": "low", "availability": "none"},
    "timeline": [
        {"time": "2026-11-02T20:51:00Z", "event": "Developer pushes commit with config/settings.py and .env to public repo acme-webapp", "actor": "Internal developer"},
        {"time": "2026-11-02T21:14:00Z", "event": "First API call with leaked key from 203.0.113.77 (GetCallerIdentity)", "actor": "Unknown actor"},
        {"time": "2026-11-02T21:20:00Z", "event": "ListBuckets and ListObjects on s3://acme-customer-exports from 203.0.113.77", "actor": "Unknown actor"},
        {"time": "2026-11-02T21:26:00Z", "event": "GetObject exports/customers.csv; data downloaded to 203.0.113.77", "actor": "Unknown actor"},
        {"time": "2026-11-02T23:02:00Z", "event": "Second source 198.51.100.23 attempts CreateUser (AccessDenied)", "actor": "Unknown actor"},
        {"time": "2026-11-03T08:05:00Z", "event": "GuardDuty finding UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration raised; SOC paged", "actor": "AWS GuardDuty"},
        {"time": "2026-11-03T08:31:00Z", "event": "SOC confirms key exposure in public repo; LeakHunter scan run on repository", "actor": "SOC"},
        {"time": "2026-11-03T09:40:00Z", "event": "Access key deactivated, repository made private, attacker IPs blocked", "actor": "SOC / Cloud Ops"},
        {"time": "2026-11-04T15:00:00Z", "event": "All secrets in repo rotated; git history rewritten; GitHub cache purge requested", "actor": "Engineering"},
        {"time": "2026-11-05T17:30:00Z", "event": "CloudTrail review complete; no further access found. Incident closed", "actor": "SOC"},
    ],
    "iocs": [
        {"type": "ip", "value": "203.0.113.77", "note": "Used leaked key; downloaded customers.csv"},
        {"type": "ip", "value": "198.51.100.23", "note": "Attempted CreateUser"},
        {"type": "domain", "value": "paste-drop.example", "note": "Key later seen on paste site"},
        {"type": "sha256", "value": "9f2c8a6e1d4b7f3a0c5e8d2b6a9f1c4e7d0a3b6c9e2f5a8d1b4c7e0a3d6f9b2c", "note": "Hash of exfiltrated customers.csv"},
    ],
    "attack_techniques": ["T1552.001", "T1078.004", "T1530"],
    "actions": {
        "containment": ["Deactivated the leaked AWS access key", "Made the GitHub repository private",
                        "Blocked 203.0.113.77 and 198.51.100.23 at the WAF and in IAM policy conditions"],
        "eradication": ["Rotated every secret found by the LeakHunter scan (AWS, GitHub, Stripe, database)",
                        "Removed secrets from git history and requested GitHub cache purge"],
        "recovery": ["Re-deployed the application with secrets from AWS Secrets Manager",
                     "Monitored CloudTrail for 48 hours for reuse of old credentials"],
    },
    "root_cause": ("Secrets were stored in plain-text config files committed to git, and the repository was "
                   "accidentally set to public. No secret scanning ran before push."),
    "recommendations": ["Make repositories private by default and require approval to publish."],
    "lessons_learned": [
        "GuardDuty detected the abuse, but 11 hours after first use; an alert on public repos would have been faster.",
        "LeakHunter quickly scoped every exposed secret, which made rotation complete in one pass.",
        "Customer data should not be exported to S3 in clear text.",
    ],
    "evidence": [
        {"severity": "high", "title": "S3 GetObject on customers.csv from unknown IP", "asset": "s3://acme-customer-exports",
         "detail": "CloudTrail event, 2026-11-02 21:26 UTC", "source": "CloudTrail"},
    ],
}


# =========================================================================== #
# CLI
# =========================================================================== #

def load_incident(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise InputError(f"Cannot read {path}: {e.strerror}")
    except json.JSONDecodeError as e:
        raise InputError(f"{path}: invalid JSON at line {e.lineno} column {e.colno}: {e.msg}")
    if not isinstance(data, dict):
        raise InputError(f"{path}: top level must be a JSON object")
    return data


def cmd_template(args) -> int:
    text = json.dumps(SAMPLE, indent=2)
    if args.output:
        if os.path.exists(args.output) and not args.force:
            print(f"[-] {args.output} exists (use --force).", file=sys.stderr)
            return 2
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"[+] Sample incident written to {args.output}. Edit it, then run: "
              f"python irgen.py generate {args.output} -o report.html")
    else:
        print(text)
    return 0


def _report_problems(errors, warnings) -> None:
    for x in errors:
        print(f"[-] {x}", file=sys.stderr)
    for w in warnings:
        print(f"[!] {w}", file=sys.stderr)


def cmd_validate(args) -> int:
    try:
        raw = load_incident(args.incident)
    except InputError as e:
        print(f"[-] {e}", file=sys.stderr)
        return 2
    inc, errors = build(raw, args.imports, os.path.dirname(os.path.abspath(args.incident)))
    _report_problems(errors, inc.warnings)
    if errors:
        print(f"[-] {len(errors)} error(s).", file=sys.stderr)
        return 1
    print(f"[+] Valid. Severity {inc.severity.upper()}, {len(inc.timeline)} timeline events, "
          f"{len(inc.evidence)} evidence items, {len(inc.iocs)} IOCs, {len(inc.techniques)} ATT&CK techniques.")
    return 0


def cmd_generate(args) -> int:
    try:
        raw = load_incident(args.incident)
    except InputError as e:
        print(f"[-] {e}", file=sys.stderr)
        return 2
    inc, errors = build(raw, args.imports, os.path.dirname(os.path.abspath(args.incident)))
    _report_problems(errors, inc.warnings)
    if errors and not args.force:
        print("[-] Fix the errors above (or use --force to generate anyway).", file=sys.stderr)
        return 1
    outputs = args.output or [os.path.splitext(args.incident)[0] + "_report.html"]
    for path in outputs:
        ext = os.path.splitext(path)[1].lower()
        renderer = {".html": render_html, ".htm": render_html, ".md": render_markdown,
                    ".json": render_json}.get(ext)
        if not renderer:
            print(f"[-] {path}: unsupported extension (use .html, .md or .json)", file=sys.stderr)
            return 2
        with open(path, "w", encoding="utf-8") as f:
            f.write(renderer(inc))
        print(f"[+] Report written: {path}")
    m = dict(metrics(inc))
    print(f"    {inc.raw.get('id')} | severity {inc.severity.upper()} | {len(inc.evidence)} findings | "
          f"{len(inc.iocs)} IOCs | {len(inc.techniques)} ATT&CK | contain {m['Time to contain']}")
    return 0


# =========================================================================== #
# Built-in test suite   ->   python irgen.py selftest
# =========================================================================== #
import copy
import tempfile
import unittest


def _sample():
    return copy.deepcopy(SAMPLE)


class ValidationTests(unittest.TestCase):
    def test_sample_is_valid(self):
        inc, errors = build(_sample())
        self.assertEqual(errors, [])
        self.assertEqual(inc.warnings, [])

    def test_missing_fields(self):
        _, errors = build({"title": "x"})
        self.assertTrue(any("id" in e for e in errors))
        self.assertTrue(any("summary" in e for e in errors))

    def test_date_order(self):
        s = _sample()
        s["dates"]["contained"] = "2026-11-01T00:00:00Z"
        _, errors = build(s)
        self.assertTrue(any("before" in e for e in errors))

    def test_bad_values(self):
        s = _sample()
        s.update(status="Done", classification="SECRET", severity="extreme")
        s["impact"]["integrity"] = "huge"
        s["attack_techniques"] = ["T15"]
        s["timeline"].append({"time": "yesterday", "event": "x"})
        _, errors = build(s)
        self.assertEqual(len(errors), 6, errors)

    def test_status_warnings(self):
        s = _sample()
        s["dates"]["resolved"] = None
        inc, errors = build(s)
        self.assertEqual(errors, [])
        self.assertTrue(any("resolved" in w for w in inc.warnings))


class EnrichmentTests(unittest.TestCase):
    def test_metrics(self):
        inc, _ = build(_sample())
        m = dict(metrics(inc))
        self.assertEqual(m["Time to detect"], "10h 51m")
        self.assertEqual(m["Time to contain"], "1h 35m")
        self.assertEqual(m["Time to resolve"], "2d 9h 25m")

    def test_severity_computed_and_declared(self):
        inc, _ = build(_sample())
        self.assertEqual(inc.severity, "high")
        s = _sample()
        s["severity"] = "low"
        inc, _ = build(s)
        self.assertEqual(inc.severity, "low")
        self.assertTrue(any("lower than the facts" in w for w in inc.warnings))

    def test_severity_critical_for_large_breach(self):
        s = _sample()
        s["data_involved"]["records"] = 50000
        self.assertEqual(build(s)[0].severity, "critical")

    def test_ioc_extraction_and_dedupe(self):
        inc, _ = build(_sample())
        ips = [i.value for i in inc.iocs if i.type == "ip"]
        self.assertEqual(sorted(ips), ["198.51.100.23", "203.0.113.77"])   # manual + timeline deduped
        self.assertIn("paste-drop.example", [i.value for i in inc.iocs])

    def test_defang(self):
        self.assertEqual(defang("ip", "203.0.113.77"), "203.0.113[.]77")
        self.assertEqual(defang("url", "https://evil.example/a.php"), "hxxps[://]evil[.]example/a.php")
        self.assertEqual(defang("email", "bob@evil.example"), "bob[@]evil[.]example")
        self.assertEqual(defang("sha256", "ab" * 32), "ab" * 32)

    def test_defang_text(self):
        t = defang_text("C2 at https://bad.example/p?x=1, from 203.0.113.9 and a@b.example; see evil.example.",
                        ("evil.example",))
        self.assertEqual(t, "C2 at hxxps[://]bad[.]example/p?x=1, from 203.0.113[.]9 and a[@]b[.]example; "
                            "see evil[.]example.")
        self.assertEqual(defang_text("config/settings.py v1.2"), "config/settings.py v1.2")

    def test_extract_types(self):
        kinds = {i.type for i in extract_iocs(
            "Beacon to http://c2.example/x from 10.0.0.5, dropper md5 " + "a" * 32 + " mail from x@bad.example")}
        self.assertEqual(kinds, {"url", "ip", "md5", "email"})

    def test_attack_listed_and_suggested(self):
        inc, _ = build(_sample())
        ids = {t[0]: t[3] for t in inc.techniques}
        self.assertFalse(ids["T1552.001"])            # analyst-listed
        self.assertTrue(ids.get("T1136"))              # suggested from "attempts CreateUser"
        self.assertNotIn("T1190", ids)                 # no exploit in this incident
        self.assertNotIn("T1041", ids)                 # S3 download is not C2 exfiltration
        self.assertNotIn("T1078", ids)                 # parent of listed T1078.004 not duplicated
        tactics = [t[2] for t in inc.techniques]
        self.assertLess(tactics.index("Initial Access / Persistence"), tactics.index("Collection"))

    def test_phishing_suggestion(self):
        s = _sample()
        s["attack_techniques"] = []
        s["summary"] = "User opened a spearphishing email with a malicious attachment that ran PowerShell."
        ids = {t[0] for t in build(s)[0].techniques}
        self.assertTrue({"T1566.001", "T1059.001"} <= ids)

    def test_recommendations(self):
        inc, _ = build(_sample())
        text = " ".join(inc.recommendations)
        self.assertIn("Make repositories private", inc.recommendations[0])
        self.assertIn("Rotate", text)
        self.assertIn("least-privilege", text)

    def test_no_duplicate_recommendations(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "lh.json")
            json.dump({"tool": "LeakHunter 1.0.0", "findings": [{"rule": "AWS secret access key", "category": "secret",
                       "severity": "critical", "file": "a.py", "line": 1, "masked": "x"}]}, open(p, "w"))
            inc, _ = build(_sample(), [p])
        self.assertEqual(sum("rotate" in r.lower() for r in inc.recommendations), 1)
        hs = Evidence("HeaderScan", "high", "CORS: wildcard origin with credentials", "https://a",
                      recommendation="Allow only specific trusted origins, never '*' with credentials.")
        inc.evidence.append(hs)
        self.assertIn(hs.recommendation + "  (auto)", build_recommendations(inc.raw, inc))
        self.assertEqual(executive_summary(inc).count("ersonal data"), 1)

    def test_notification_notes(self):
        inc, _ = build(_sample())
        notes = " ".join(notification_notes(inc.raw, inc))
        self.assertIn("72 hours", notes)
        self.assertIn("2026-11-06 08:05 UTC", notes)
        self.assertIn("PCI DSS", notes)


class ImportTests(unittest.TestCase):
    def _write(self, d, name, obj):
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj))
        return p

    def test_all_importers(self):
        with tempfile.TemporaryDirectory() as d:
            lh = self._write(d, "lh.json", {"tool": "LeakHunter 1.0.0", "findings": [
                {"rule": "AWS secret access key", "category": "secret", "severity": "critical",
                 "file": "config/settings.py", "line": 4, "masked": "FxFk****vo"}]})
            hs = self._write(d, "hs.json", {"tool": "HeaderScan 1.0.0", "results": [
                {"url": "https://a", "final_url": "https://a/", "findings": [
                    {"severity": "high", "title": "Strict-Transport-Security missing", "fix": "Add HSTS"},
                    {"severity": "pass", "title": "ok"}]}]})
            sarif = self._write(d, "x.sarif", {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep"}},
                "results": [{"ruleId": "sqli", "level": "error", "message": {"text": "SQL injection"},
                             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                                                                 "region": {"startLine": 9}}}]}]}]})
            c = self._write(d, "f.csv", "Severity,Title,Asset\nHigh,Open RDP port,10.0.0.8\n")
            ev = []
            for p in (lh, hs, sarif, c):
                ev += import_file(p)
            self.assertEqual([(x.source, x.severity) for x in ev],
                             [("LeakHunter", "critical"), ("HeaderScan", "high"), ("Semgrep", "high"), ("f.csv", "high")])
            self.assertEqual(ev[2].asset, "app.py:9")
            self.assertIn("rotate", ev[0].recommendation)

    def test_bad_import(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(InputError):
                import_file(self._write(d, "x.json", {"what": 1}))
            with self.assertRaises(InputError):
                import_file(os.path.join(d, "missing.json"))


class RenderTests(unittest.TestCase):
    def test_html_escapes_input(self):
        s = _sample()
        s["title"] = "<script>alert(1)</script>"
        s["timeline"][0]["event"] = "<img src=x onerror=alert(1)>"
        out = render_html(build(s)[0])
        self.assertNotIn("<script>alert", out)
        self.assertNotIn("<img src=x", out)
        self.assertIn("&lt;script&gt;", out)

    def test_html_and_markdown_content(self):
        inc, _ = build(_sample())
        for out in (render_html(inc), render_markdown(inc)):
            for needle in ("IR-2026-0042", "TLP:AMBER", "203.0.113[.]77", "T1552.001", "1h 35m", "Lessons learned"):
                self.assertIn(needle, out)
            self.assertNotIn("203.0.113.77", out)       # never printed live, even in the timeline
            self.assertNotIn("paste-drop.example", out)
            self.assertIn("a security incident (unauthorized access / credential leak)", out)

    def test_markdown_escapes_pipes(self):
        s = _sample()
        s["timeline"][0]["event"] = "a | b"
        self.assertIn("a \\| b", render_markdown(build(s)[0]))

    def test_json_output(self):
        data = json.loads(render_json(build(_sample())[0]))
        self.assertEqual(data["severity"], "high")
        self.assertEqual(data["metrics"]["Time to contain"], "1h 35m")


class CLITests(unittest.TestCase):
    def test_template_validate_generate(self):
        with tempfile.TemporaryDirectory() as d:
            inc = os.path.join(d, "incident.json")
            outs = [os.path.join(d, n) for n in ("r.html", "r.md", "r.json")]
            devnull, old = open(os.devnull, "w"), (sys.stdout, sys.stderr)
            sys.stdout = sys.stderr = devnull
            try:
                self.assertEqual(main(["template", "-o", inc]), 0)
                self.assertEqual(main(["template", "-o", inc]), 2)            # no overwrite
                self.assertEqual(main(["validate", inc]), 0)
                self.assertEqual(main(["generate", inc] + sum((["-o", o] for o in outs), [])), 0)
                self.assertEqual(main(["generate", inc, "-o", os.path.join(d, "r.pdf")]), 2)
                bad = json.load(open(inc))
                bad["dates"]["detected"] = "not a date"
                json.dump(bad, open(inc, "w"))
                self.assertEqual(main(["validate", inc]), 1)
                self.assertEqual(main(["generate", inc, "-o", outs[0]]), 1)
                open(inc, "w").write("{broken")
                self.assertEqual(main(["validate", inc]), 2)
            finally:
                sys.stdout, sys.stderr = old
                devnull.close()
            self.assertTrue(all(os.path.getsize(o) > 1000 for o in outs))


def cmd_selftest(args) -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for case in (ValidationTests, EnrichmentTests, ImportTests, RenderTests, CLITests):
        suite.addTests(loader.loadTestsFromTestCase(case))
    result = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    return 0 if result.wasSuccessful() else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="irgen", description="Generate professional cybersecurity incident reports.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("template", help="write a sample incident file to start from")
    t.add_argument("-o", "--output", help="file to write (default: print)")
    t.add_argument("-f", "--force", action="store_true", help="overwrite if it exists")
    t.set_defaults(func=cmd_template)

    for name, func, helptext in (("validate", cmd_validate, "check an incident file"),
                                 ("generate", cmd_generate, "build the report")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("incident", help="incident JSON file")
        s.add_argument("--import", dest="imports", action="append", default=[], metavar="FILE",
                       help="tool output to add as evidence (LeakHunter/HeaderScan JSON, SARIF, CSV)")
        if name == "generate":
            s.add_argument("-o", "--output", action="append", metavar="FILE",
                           help="output file: .html, .md or .json (repeatable)")
            s.add_argument("-f", "--force", action="store_true", help="generate even if validation fails")
        s.set_defaults(func=func)

    x = sub.add_parser("selftest", help="run the built-in test suite")
    x.add_argument("-v", "--verbose", action="store_true")
    x.set_defaults(func=cmd_selftest)
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
