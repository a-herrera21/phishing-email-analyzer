#!/usr/bin/env python3
"""
Phishing Email Analyzer
========================
Parses .eml files and performs multi-signal phishing detection:
  - SPF / DKIM / DMARC authentication checks
  - From/Reply-To/Return-Path spoofing detection
  - URL extraction + suspicious domain analysis
  - VirusTotal URL reputation checks
  - Phishing language heuristics
  - Suspicious attachment detection
  - Final verdict: LIKELY PHISHING / SUSPICIOUS / LIKELY LEGITIMATE

Usage:
    python analyze.py --file suspicious.eml
    python analyze.py --file email.eml --output report.md --no-vt
"""

import argparse
import email
import email.policy
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime
from email import message_from_file
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests

# ─── Version ─────────────────────────────────────────────────────────────────
VERSION = "1.0.0"

# ─── Scoring weights ─────────────────────────────────────────────────────────
# Each triggered signal adds points to the risk score.
# Final verdict:  >= 60 → LIKELY PHISHING
#                 >= 25 → SUSPICIOUS
#                  < 25 → LIKELY LEGITIMATE

SCORE_SPF_FAIL          = 20
SCORE_SPF_SOFTFAIL      = 10
SCORE_DKIM_FAIL         = 20
SCORE_DMARC_FAIL        = 20
SCORE_SPOOFED_REPLY_TO  = 25
SCORE_SPOOFED_RETURN    = 20
SCORE_DOMAIN_MISMATCH   = 15
SCORE_LOOKALIKE_DOMAIN  = 20
SCORE_IP_URL            = 25
SCORE_SHORTENER_URL     = 15
SCORE_VT_MALICIOUS      = 35
SCORE_VT_SUSPICIOUS     = 20
SCORE_PHISH_LANG        = 8   # per keyword hit, capped at 40
SCORE_PHISH_LANG_CAP    = 40
SCORE_SUSPICIOUS_ATTACH = 30

VERDICT_PHISHING    = 60
VERDICT_SUSPICIOUS  = 25

# ─── Known URL shorteners ─────────────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "dlvr.it", "ift.tt", "short.link", "rebrand.ly", "cutt.ly",
    "is.gd", "tiny.cc", "shorturl.at", "tr.im",
}

# ─── Suspicious TLDs ──────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".xyz", ".ru", ".cn", ".tk", ".pw", ".top", ".club", ".icu",
    ".gq", ".ml", ".ga", ".cf", ".work", ".link", ".click",
}

# ─── Phishing language patterns ───────────────────────────────────────────────
PHISHING_PATTERNS = [
    (re.compile(r"\burgent\b", re.I),               "urgency: 'urgent'"),
    (re.compile(r"\bimmediately\b", re.I),           "urgency: 'immediately'"),
    (re.compile(r"\bwithin\s+\d+\s+hour", re.I),    "urgency: time pressure"),
    (re.compile(r"\baccount.*limit", re.I),          "threat: account limited"),
    (re.compile(r"\bsuspend", re.I),                 "threat: suspension threat"),
    (re.compile(r"\bverify\s+your\s+(account|identity|information)", re.I), "request: verify account"),
    (re.compile(r"\bclick\s+here\b", re.I),          "CTA: click here"),
    (re.compile(r"\bconfirm\s+your\b", re.I),        "request: confirm info"),
    (re.compile(r"\bpassword\s+expire", re.I),       "threat: password expiry"),
    (re.compile(r"\bunauthorized\s+(access|login|activity)", re.I), "alert: unauthorized access"),
    (re.compile(r"\bsuspicious\s+activity\b", re.I),"alert: suspicious activity"),
    (re.compile(r"\bpermanently\s+(suspend|close|lock)", re.I), "threat: permanent action"),
    (re.compile(r"\bfunds?\s+(frozen|suspended)\b", re.I), "threat: funds frozen"),
    (re.compile(r"\baction\s+required\b", re.I),    "CTA: action required"),
    (re.compile(r"\bsecurity\s+alert\b", re.I),     "alert: security alert"),
    (re.compile(r"\bupdate\s+your\s+(payment|billing|account)\b", re.I), "request: update payment"),
    (re.compile(r"\bfailure\s+to\s+(act|comply|respond)\b", re.I), "threat: failure to act"),
]

# ─── Suspicious attachment extensions ────────────────────────────────────────
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".js",
    ".jar", ".ps1", ".psm1", ".hta", ".msi", ".reg", ".dll",
}

# ─── Regex ────────────────────────────────────────────────────────────────────
URL_RE = re.compile(
    r"https?://[^\s\"\'\<\>\)\(,]+"
    r"|www\.[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}[^\s\"\'\<\>\)\(,]*",
    re.I,
)

IP_URL_RE = re.compile(
    r"https?://(?:\d{1,3}\.){3}\d{1,3}",
    re.I,
)

DOMAIN_FROM_RE = re.compile(r"@([\w.\-]+?)>?\s*$")


# ─── Email Parser ─────────────────────────────────────────────────────────────

class EmailParser:
    """Parses a .eml file into structured components."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.msg = None
        self.from_header = ""
        self.from_name = ""
        self.from_domain = ""
        self.reply_to = ""
        self.reply_to_domain = ""
        self.return_path = ""
        self.return_path_domain = ""
        self.subject = ""
        self.date = ""
        self.auth_results = ""
        self.body_text = ""
        self.body_html = ""
        self.attachments: list[dict] = []
        self.raw_headers: dict = {}

    def parse(self) -> None:
        path = Path(self.filepath)
        if not path.exists():
            raise FileNotFoundError(f"Email file not found: {self.filepath}")
        if path.stat().st_size == 0:
            raise ValueError(f"Email file is empty: {self.filepath}")

        with open(path, "r", errors="replace") as f:
            self.msg = email.message_from_file(f, policy=email.policy.compat32)

        self._extract_headers()
        self._extract_body()
        self._extract_attachments()

    def _extract_headers(self) -> None:
        self.from_header   = self.msg.get("From", "")
        self.reply_to      = self.msg.get("Reply-To", "")
        self.return_path   = self.msg.get("Return-Path", "")
        self.subject       = self.msg.get("Subject", "")
        self.date          = self.msg.get("Date", "")
        self.auth_results  = self.msg.get("Authentication-Results", "")

        # Parse from domain
        m = DOMAIN_FROM_RE.search(self.from_header)
        if m:
            self.from_domain = m.group(1).lower()
        # Parse from display name
        if "<" in self.from_header:
            self.from_name = self.from_header.split("<")[0].strip().strip('"')
        else:
            self.from_name = self.from_header

        # Parse reply-to domain
        m = DOMAIN_FROM_RE.search(self.reply_to)
        if m:
            self.reply_to_domain = m.group(1).lower()

        # Parse return-path domain
        m = DOMAIN_FROM_RE.search(self.return_path)
        if m:
            self.return_path_domain = m.group(1).lower()

        # Store all headers for reference
        for key in self.msg.keys():
            self.raw_headers[key] = self.msg.get(key, "")

    def _extract_body(self) -> None:
        if self.msg.is_multipart():
            for part in self.msg.walk():
                ctype = part.get_content_type()
                disp  = str(part.get("Content-Disposition", ""))
                if "attachment" in disp:
                    continue
                if ctype == "text/plain":
                    try:
                        self.body_text += part.get_payload(decode=True).decode("utf-8", errors="replace")
                    except Exception:
                        pass
                elif ctype == "text/html":
                    try:
                        self.body_html += part.get_payload(decode=True).decode("utf-8", errors="replace")
                    except Exception:
                        pass
        else:
            payload = self.msg.get_payload()
            if isinstance(payload, str):
                if self.msg.get_content_type() == "text/html":
                    self.body_html = payload
                else:
                    self.body_text = payload

    def _extract_attachments(self) -> None:
        if not self.msg.is_multipart():
            return
        for part in self.msg.walk():
            disp = str(part.get("Content-Disposition", ""))
            name = part.get_filename() or part.get_param("name") or ""
            if "attachment" in disp or name:
                self.attachments.append({
                    "filename": name,
                    "content_type": part.get_content_type(),
                })

    @property
    def full_body(self) -> str:
        return self.body_text + " " + self.body_html


# ─── Analysis Engine ──────────────────────────────────────────────────────────

class PhishingAnalyzer:
    """Runs all detection checks and computes a risk score + verdict."""

    def __init__(self, parser: EmailParser):
        self.parser   = parser
        self.score    = 0
        self.findings = []   # list of (category, description, points)
        self.urls: list[str] = []
        self.vt_results: list[dict] = []

    # ── Auth checks ───────────────────────────────────────────────────────────

    def check_authentication(self) -> None:
        auth = self.parser.auth_results.lower()
        if not auth:
            # No Authentication-Results header at all — flag gently
            self._add("AUTH", "No Authentication-Results header found", 5)
            return

        # SPF
        if "spf=fail" in auth:
            self._add("SPF", "SPF check FAILED — sending server not authorized for this domain", SCORE_SPF_FAIL)
        elif "spf=softfail" in auth:
            self._add("SPF", "SPF SOFTFAIL — domain owner discourages this sender", SCORE_SPF_SOFTFAIL)
        elif "spf=none" in auth:
            self._add("SPF", "SPF=none — no SPF record published for sending domain", 8)
        elif "spf=pass" in auth:
            self._add("SPF", "SPF passed ✓", 0)

        # DKIM
        if "dkim=fail" in auth:
            self._add("DKIM", "DKIM signature FAILED — message may have been tampered", SCORE_DKIM_FAIL)
        elif "dkim=none" in auth:
            self._add("DKIM", "DKIM=none — email was not signed", 10)
        elif "dkim=pass" in auth:
            self._add("DKIM", "DKIM passed ✓", 0)

        # DMARC
        if "dmarc=fail" in auth:
            self._add("DMARC", "DMARC check FAILED — email does not align with domain policy", SCORE_DMARC_FAIL)
        elif "dmarc=none" in auth:
            self._add("DMARC", "DMARC=none — no DMARC policy found", 8)
        elif "dmarc=pass" in auth:
            self._add("DMARC", "DMARC passed ✓", 0)

    # ── Spoofing / header mismatch checks ─────────────────────────────────────

    def check_spoofing(self) -> None:
        fd = self.parser.from_domain
        rt = self.parser.reply_to_domain
        rp = self.parser.return_path_domain

        # Reply-To mismatch
        if rt and rt != fd:
            self._add("SPOOFING", f"Reply-To domain ({rt}) differs from From domain ({fd}) — replies go to attacker", SCORE_SPOOFED_REPLY_TO)

        # Return-Path mismatch
        if rp and rp != fd:
            self._add("SPOOFING", f"Return-Path domain ({rp}) differs from From domain ({fd}) — bounce destination mismatch", SCORE_SPOOFED_RETURN)

        # Display name impersonation check
        # If display name contains a well-known brand but domain doesn't match
        brand_domain_map = {
            "paypal":     "paypal.com",
            "microsoft":  "microsoft.com",
            "chase":      "chase.com",
            "apple":      "apple.com",
            "amazon":     "amazon.com",
            "google":     "google.com",
            "facebook":   "facebook.com",
            "netflix":    "netflix.com",
            "bank of america": "bankofamerica.com",
            "wells fargo": "wellsfargo.com",
        }
        name_lower = self.parser.from_name.lower()
        for brand, legit_domain in brand_domain_map.items():
            if brand in name_lower and legit_domain not in fd:
                self._add("SPOOFING", f"Display name claims to be '{brand.title()}' but sending domain is '{fd}' not '{legit_domain}'", SCORE_DOMAIN_MISMATCH)
                break

    # ── URL extraction ────────────────────────────────────────────────────────

    def extract_urls(self) -> list[str]:
        body = self.parser.full_body
        raw_urls = URL_RE.findall(body)
        # Clean up trailing punctuation
        cleaned = []
        for u in raw_urls:
            u = u.rstrip(".,;:!?\"'")
            if u not in cleaned:
                cleaned.append(u)
        self.urls = cleaned
        return cleaned

    # ── URL analysis ──────────────────────────────────────────────────────────

    def check_urls(self) -> None:
        if not self.urls:
            return

        for url in self.urls:
            # IP-based URL
            if IP_URL_RE.match(url):
                self._add("URL", f"IP-based URL (bypasses domain filtering): {url}", SCORE_IP_URL)
                continue

            try:
                parsed = urlparse(url if url.startswith("http") else "http://" + url)
                host = parsed.netloc.lower().split(":")[0]
            except Exception:
                continue

            # URL shortener
            if host in URL_SHORTENERS:
                self._add("URL", f"URL shortener detected (hides real destination): {url}", SCORE_SHORTENER_URL)
                continue

            # Suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if host.endswith(tld):
                    self._add("URL", f"Suspicious TLD '{tld}' in URL: {url}", 10)
                    break

            # Lookalike / typosquatting detection
            lookalike_indicators = [
                ("paypal",    ["paypa1", "paypa-l", "paypal-", "secure-paypal", "paypal.support"]),
                ("microsoft", ["micros0ft", "microsoft-", "micro5oft", "microsoft.support"]),
                ("amazon",    ["amaz0n", "amazon-", "amazonn", "amazon.support"]),
                ("google",    ["g00gle", "go0gle", "google-", "google.support"]),
                ("apple",     ["app1e", "apple-", "appleID", "apple.support"]),
                ("chase",     ["cha5e", "chase-", "chase.secure", "chaseonline"]),
            ]
            for brand, patterns in lookalike_indicators:
                for pat in patterns:
                    if pat in host:
                        self._add("URL", f"Lookalike domain impersonating '{brand}': {host}", SCORE_LOOKALIKE_DOMAIN)
                        break

            # Suspicious keyword in domain
            suspicious_keywords = ["secure-", "verify-", "login-", "account-", "update-", "-support", "helpdesk-"]
            for kw in suspicious_keywords:
                if kw in host:
                    self._add("URL", f"Suspicious keyword '{kw}' in domain: {host}", 8)
                    break

    # ── VirusTotal checks ─────────────────────────────────────────────────────

    def check_virustotal(self, api_key: Optional[str] = None) -> None:
        key = api_key or os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
        if not key:
            self._add("VIRUSTOTAL", "VirusTotal check skipped — set VIRUSTOTAL_API_KEY env var (free at virustotal.com)", 0)
            return

        if not self.urls:
            return

        # Check top 3 non-shortener, non-legitimate URLs to stay within free rate limits
        urls_to_check = [
            u for u in self.urls
            if not any(s in u for s in ["github.com", "amazon.com", "google.com", "microsoft.com"])
        ][:3]

        if not urls_to_check:
            return

        import base64
        for url in urls_to_check:
            try:
                # VT API v3 — encode URL as base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": key},
                    timeout=15,
                )

                if resp.status_code == 404:
                    # URL not in VT database yet — submit it
                    submit = requests.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers={"x-apikey": key},
                        data={"url": url},
                        timeout=15,
                    )
                    if submit.status_code == 200:
                        self.vt_results.append({"url": url, "status": "submitted", "malicious": 0, "suspicious": 0})
                    continue

                if resp.status_code == 429:
                    self._add("VIRUSTOTAL", "VirusTotal rate limit hit (free tier: 4 req/min). Some URLs not checked.", 0)
                    break

                resp.raise_for_status()
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious  = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                self.vt_results.append({
                    "url": url,
                    "status": "found",
                    "malicious": malicious,
                    "suspicious": suspicious,
                })

                if malicious > 0:
                    self._add("VIRUSTOTAL", f"VirusTotal: {malicious} engines flagged as MALICIOUS: {url}", SCORE_VT_MALICIOUS)
                elif suspicious > 0:
                    self._add("VIRUSTOTAL", f"VirusTotal: {suspicious} engines flagged as suspicious: {url}", SCORE_VT_SUSPICIOUS)

                # Free tier: 4 requests/minute
                time.sleep(16)

            except requests.Timeout:
                self.vt_results.append({"url": url, "status": "timeout", "malicious": 0, "suspicious": 0})
            except Exception as e:
                self.vt_results.append({"url": url, "status": f"error: {e}", "malicious": 0, "suspicious": 0})

    # ── Phishing language heuristics ──────────────────────────────────────────

    def check_phishing_language(self) -> None:
        body = self.parser.full_body
        subject = self.parser.subject
        combined = body + " " + subject

        hits = []
        for pattern, label in PHISHING_PATTERNS:
            if pattern.search(combined):
                hits.append(label)

        if hits:
            score = min(len(hits) * SCORE_PHISH_LANG, SCORE_PHISH_LANG_CAP)
            desc = "Phishing language detected: " + ", ".join(hits[:8])
            if len(hits) > 8:
                desc += f" (+{len(hits)-8} more)"
            self._add("LANGUAGE", desc, score)

    # ── Attachment checks ─────────────────────────────────────────────────────

    def check_attachments(self) -> None:
        for att in self.parser.attachments:
            filename = att["filename"]
            if not filename:
                continue

            # Double extension attack (e.g. invoice.pdf.exe)
            parts = filename.split(".")
            if len(parts) >= 3:
                real_ext = "." + parts[-1].lower()
                if real_ext in SUSPICIOUS_EXTENSIONS:
                    self._add("ATTACHMENT", f"Double-extension suspicious file: '{filename}' — real extension is {real_ext}", SCORE_SUSPICIOUS_ATTACH)
                    continue

            # Direct executable
            ext = Path(filename).suffix.lower()
            if ext in SUSPICIOUS_EXTENSIONS:
                self._add("ATTACHMENT", f"Suspicious attachment type '{ext}': {filename}", SCORE_SUSPICIOUS_ATTACH)

    # ── Verdict ───────────────────────────────────────────────────────────────

    def verdict(self) -> str:
        if self.score >= VERDICT_PHISHING:
            return "🚨 LIKELY PHISHING"
        elif self.score >= VERDICT_SUSPICIOUS:
            return "⚠️  SUSPICIOUS"
        else:
            return "✅ LIKELY LEGITIMATE"

    def verdict_short(self) -> str:
        if self.score >= VERDICT_PHISHING:
            return "LIKELY PHISHING"
        elif self.score >= VERDICT_SUSPICIOUS:
            return "SUSPICIOUS"
        else:
            return "LIKELY LEGITIMATE"

    # ── Internal helper ───────────────────────────────────────────────────────

    def _add(self, category: str, description: str, points: int) -> None:
        self.findings.append((category, description, points))
        self.score += points

    def run_all(self, vt_api_key: Optional[str] = None, skip_vt: bool = False) -> None:
        self.check_authentication()
        self.check_spoofing()
        self.extract_urls()
        self.check_urls()
        self.check_phishing_language()
        self.check_attachments()
        if not skip_vt:
            self.check_virustotal(vt_api_key)


# ─── Report Builder ───────────────────────────────────────────────────────────

def build_report(parser: EmailParser, analyzer: PhishingAnalyzer, source_file: str) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    verdict = analyzer.verdict()
    score   = analyzer.score

    # Group findings by category
    cats = defaultdict(list)
    for cat, desc, pts in analyzer.findings:
        cats[cat].append((desc, pts))

    lines = [
        "# 🔍 Phishing Email Analysis Report",
        "",
        f"**Generated:** {now}",
        f"**Source file:** `{source_file}`",
        f"**Subject:** {parser.subject}",
        f"**From:** {parser.from_header}",
        f"**Reply-To:** {parser.reply_to or '(not set)'}",
        f"**Return-Path:** {parser.return_path or '(not set)'}",
        f"**Date:** {parser.date}",
        "",
        "---",
        "",
        f"## 🏁 Verdict: {verdict}",
        f"**Risk Score: {score}** (0-25 = Legitimate | 25-59 = Suspicious | 60+ = Phishing)",
        "",
        "---",
        "",
    ]

    # Authentication
    lines += ["## 🔐 Email Authentication (SPF / DKIM / DMARC)", ""]
    if "AUTH" in cats or "SPF" in cats or "DKIM" in cats or "DMARC" in cats:
        for cat in ["AUTH", "SPF", "DKIM", "DMARC"]:
            for desc, pts in cats.get(cat, []):
                flag = "🔴" if pts >= 15 else ("🟡" if pts > 0 else "🟢")
                score_tag = f"+{pts}" if pts > 0 else "no penalty"
                lines.append(f"- {flag} {desc} `[{score_tag}]`")
    else:
        lines.append("- 🟢 No authentication issues found")
    lines.append("")

    # Spoofing
    lines += ["## 👤 Sender Spoofing / Header Analysis", ""]
    if "SPOOFING" in cats:
        for desc, pts in cats["SPOOFING"]:
            flag = "🔴" if pts >= 20 else "🟡"
            lines.append(f"- {flag} {desc} `[+{pts}]`")
    else:
        lines.append("- 🟢 No spoofing indicators detected")
    lines.append("")

    # URLs
    lines += ["## 🌐 URL Analysis", ""]
    if analyzer.urls:
        lines.append(f"**{len(analyzer.urls)} URL(s) found in email body:**")
        lines.append("")
        for u in analyzer.urls:
            lines.append(f"- `{u}`")
        lines.append("")
    else:
        lines.append("No URLs found in email body.")
        lines.append("")

    if "URL" in cats:
        lines.append("**URL Flags:**")
        lines.append("")
        for desc, pts in cats["URL"]:
            flag = "🔴" if pts >= 20 else "🟡"
            lines.append(f"- {flag} {desc} `[+{pts}]`")
    else:
        lines.append("- 🟢 No suspicious URL patterns detected")
    lines.append("")

    # VirusTotal
    lines += ["## 🦠 VirusTotal URL Reputation", ""]
    if analyzer.vt_results:
        for r in analyzer.vt_results:
            url = r["url"]
            status = r["status"]
            if status == "found":
                m, s = r["malicious"], r["suspicious"]
                if m > 0:
                    lines.append(f"- 🔴 **MALICIOUS** ({m} engines): `{url}`")
                elif s > 0:
                    lines.append(f"- 🟡 Suspicious ({s} engines): `{url}`")
                else:
                    lines.append(f"- 🟢 Clean (0 detections): `{url}`")
            elif status == "submitted":
                lines.append(f"- ℹ️  Submitted to VT for analysis (not yet in database): `{url}`")
            else:
                lines.append(f"- ⚠️  Lookup status '{status}': `{url}`")
    else:
        if any("skipped" in d.lower() for _, d, _ in analyzer.findings if _ == 0):
            lines.append("- ℹ️  VirusTotal check skipped — no API key configured")
        else:
            lines.append("- ℹ️  No URLs checked against VirusTotal")
    if "VIRUSTOTAL" in cats:
        for desc, pts in cats["VIRUSTOTAL"]:
            if pts == 0:
                lines.append(f"- ℹ️  {desc}")
    lines.append("")

    # Language
    lines += ["## 💬 Phishing Language / Content Analysis", ""]
    if "LANGUAGE" in cats:
        for desc, pts in cats["LANGUAGE"]:
            lines.append(f"- 🟡 {desc} `[+{pts}]`")
    else:
        lines.append("- 🟢 No phishing language patterns detected")
    lines.append("")

    # Attachments
    lines += ["## 📎 Attachment Analysis", ""]
    if parser.attachments:
        lines.append(f"**{len(parser.attachments)} attachment(s) found:**")
        for att in parser.attachments:
            lines.append(f"- `{att['filename']}` ({att['content_type']})")
        lines.append("")
        if "ATTACHMENT" in cats:
            for desc, pts in cats["ATTACHMENT"]:
                lines.append(f"- 🔴 {desc} `[+{pts}]`")
        else:
            lines.append("- 🟢 No suspicious attachment types detected")
    else:
        lines.append("- ℹ️  No attachments found")
    lines.append("")

    # Score summary
    lines += [
        "---",
        "",
        "## 📊 Score Breakdown",
        "",
        "| Category | Finding | Points |",
        "|----------|---------|--------|",
    ]
    for cat, desc, pts in analyzer.findings:
        if pts > 0:
            # Truncate long descriptions
            short = desc[:70] + "..." if len(desc) > 70 else desc
            lines.append(f"| {cat} | {short} | +{pts} |")

    lines += [
        "",
        f"**Total Risk Score: {score}**",
        f"**Verdict: {analyzer.verdict_short()}**",
        "",
        "---",
        f"*Report generated by phishing-email-analyzer v{VERSION} — github.com/a-herrera21/phishing-email-analyzer*",
    ]

    return "\n".join(lines)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser_cli = argparse.ArgumentParser(
        description="Phishing Email Analyzer — multi-signal .eml file analysis for SOC triage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze.py --file suspicious.eml
  python analyze.py --file email.eml --output report.md
  python analyze.py --file email.eml --no-vt
        """,
    )
    parser_cli.add_argument("--file", required=True, help="Path to the .eml file to analyze")
    parser_cli.add_argument("--output", default=None, help="Save markdown report to this file (default: auto-named)")
    parser_cli.add_argument("--no-vt", action="store_true", help="Skip VirusTotal URL checks")
    parser_cli.add_argument("--vt-key", default=None, help="VirusTotal API key (or set VIRUSTOTAL_API_KEY env var)")
    args = parser_cli.parse_args()

    print(f"\n{'='*60}")
    print(f"  Phishing Email Analyzer v{VERSION}")
    print(f"{'='*60}\n")

    # ── Parse ──────────────────────────────────────────────────────────────
    print(f"[1/5] Parsing email: {args.file}")
    ep = EmailParser(args.file)
    try:
        ep.parse()
    except FileNotFoundError as e:
        print(f"\n❌ {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"\n❌ {e}", file=sys.stderr)
        sys.exit(1)

    print(f"      From:    {ep.from_header}")
    print(f"      Subject: {ep.subject}")
    print(f"      Body length: {len(ep.full_body)} chars | Attachments: {len(ep.attachments)}")

    # ── Analyze ────────────────────────────────────────────────────────────
    analyzer = PhishingAnalyzer(ep)

    print(f"\n[2/5] Checking authentication (SPF/DKIM/DMARC)...")
    analyzer.check_authentication()
    auth_issues = [(c,d,p) for c,d,p in analyzer.findings if c in ("SPF","DKIM","DMARC","AUTH") and p > 0]
    if auth_issues:
        for _, d, p in auth_issues:
            print(f"      ⚠️  {d}")
    else:
        print(f"      ✓ Authentication looks clean")

    print(f"\n[3/5] Checking for spoofing / header mismatches...")
    analyzer.check_spoofing()
    spoof_issues = [(c,d,p) for c,d,p in analyzer.findings if c == "SPOOFING"]
    if spoof_issues:
        for _, d, _ in spoof_issues:
            print(f"      🚨 {d}")
    else:
        print(f"      ✓ No spoofing detected")

    print(f"\n[4/5] Extracting and analyzing URLs...")
    analyzer.extract_urls()
    print(f"      Found {len(analyzer.urls)} URL(s)")
    analyzer.check_urls()
    analyzer.check_phishing_language()
    analyzer.check_attachments()
    url_issues = [(c,d,p) for c,d,p in analyzer.findings if c == "URL" and p > 0]
    for _, d, _ in url_issues[:3]:
        print(f"      ⚠️  {d}")

    if not args.no_vt:
        vt_key = args.vt_key or os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
        if vt_key:
            print(f"\n      Checking {min(len(analyzer.urls), 3)} URL(s) against VirusTotal...")
            analyzer.check_virustotal(vt_key)
        else:
            print(f"\n      ℹ️  No VirusTotal key — skipping (set VIRUSTOTAL_API_KEY to enable)")
            analyzer.check_virustotal(None)
    else:
        print(f"\n      ℹ️  VirusTotal check skipped (--no-vt)")

    print(f"\n[5/5] Computing verdict...")
    verdict = analyzer.verdict()
    print(f"\n{'='*60}")
    print(f"  VERDICT: {verdict}")
    print(f"  RISK SCORE: {analyzer.score}")
    print(f"{'='*60}\n")

    # Print triggered signals
    triggered = [(c,d,p) for c,d,p in analyzer.findings if p > 0]
    if triggered:
        print("Triggered signals:")
        for cat, desc, pts in triggered:
            print(f"  [{cat}] +{pts:2d}  {desc}")
    print()

    # ── Report ─────────────────────────────────────────────────────────────
    report_md = build_report(ep, analyzer, args.file)

    output_path = args.output
    if not output_path:
        stem = Path(args.file).stem
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"report_{stem}_{ts}.md"

    with open(output_path, "w") as f:
        f.write(report_md)

    print(f"✅ Report saved to: {output_path}\n")


if __name__ == "__main__":
    main()
