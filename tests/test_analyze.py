"""
Unit tests for analyze.py — header parsing, URL extraction, detection logic.
All tests run without any API keys required.
"""
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from analyze import (
    EmailParser, PhishingAnalyzer,
    URL_RE, IP_URL_RE, DOMAIN_FROM_RE,
    VERDICT_PHISHING, VERDICT_SUSPICIOUS,
)


# ─── Sample .eml content ─────────────────────────────────────────────────────

PHISHING_EML = """\
From: "PayPal Security" <security@paypa1-support.com>
To: victim@example.com
Subject: URGENT: Verify your account now
Date: Mon, 14 Sep 2026 08:00:00 -0500
Message-ID: <fake@paypa1-support.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Return-Path: <bounce@evil.ru>
Reply-To: <collect@attacker.com>
Authentication-Results: mx.example.com;
       spf=fail smtp.mailfrom=paypa1-support.com;
       dkim=none;
       dmarc=fail action=none header.from=paypa1-support.com

Dear Customer,
URGENT: Your account has been limited. You must verify immediately or it will be suspended.
Click here: http://paypa1-secure.xyz/verify
Also try: http://185.220.101.47/login.php
Short link: https://bit.ly/fakepaypal
"""

LEGIT_EML = """\
From: "GitHub" <noreply@github.com>
To: developer@example.com
Subject: Your pull request was merged
Date: Mon, 14 Sep 2026 16:00:00 +0000
Message-ID: <pr123@github.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Return-Path: <noreply@github.com>
Reply-To: <noreply@github.com>
Authentication-Results: mx.example.com;
       spf=pass smtp.mailfrom=github.com;
       dkim=pass header.i=@github.com;
       dmarc=pass header.from=github.com

Hi developer,
Your pull request #42 'Fix authentication bug' was merged into main.
View it at: https://github.com/yourorg/repo/pull/42
"""

ATTACHMENT_EML = """\
From: "IT Support" <support@company.com>
To: employee@company.com
Subject: Important document attached
Date: Mon, 14 Sep 2026 09:00:00 +0000
Message-ID: <attach@company.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"
Return-Path: <support@company.com>
Authentication-Results: mx.company.com;
       spf=pass smtp.mailfrom=company.com;
       dkim=pass header.i=@company.com;
       dmarc=pass header.from=company.com

--BOUNDARY
Content-Type: text/plain

Please see the attached document.

--BOUNDARY
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"

FAKEBINARYDATA
--BOUNDARY--
"""

NO_AUTH_EML = """\
From: "Someone" <user@somedomain.com>
To: target@example.com
Subject: Hello
Date: Mon, 14 Sep 2026 10:00:00 +0000
Message-ID: <msg@somedomain.com>
Content-Type: text/plain

Hi there, just a normal email with no auth headers.
Visit https://example.com for more info.
"""


def write_eml(content: str) -> str:
    """Write content to a temp .eml file and return the path."""
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=".eml", delete=False)
    tf.write(content)
    tf.close()
    return tf.name


# ─── Regex tests ──────────────────────────────────────────────────────────────

class TestRegex:
    def test_url_re_http(self):
        urls = URL_RE.findall("Visit http://example.com/page?id=1 today")
        assert "http://example.com/page?id=1" in urls

    def test_url_re_https(self):
        urls = URL_RE.findall("Go to https://secure.site/login")
        assert "https://secure.site/login" in urls

    def test_url_re_www(self):
        urls = URL_RE.findall("See www.example.com for details")
        assert any("www.example.com" in u for u in urls)

    def test_url_re_no_false_positive(self):
        assert URL_RE.findall("no urls here at all") == []

    def test_ip_url_re_matches(self):
        assert IP_URL_RE.match("http://185.220.101.47/login.php") is not None

    def test_ip_url_re_no_match_on_domain(self):
        assert IP_URL_RE.match("https://example.com/page") is None

    def test_domain_from_re(self):
        m = DOMAIN_FROM_RE.search("John Doe <john@example.com>")
        assert m is not None
        assert m.group(1) == "example.com"

    def test_domain_from_re_bare_email(self):
        m = DOMAIN_FROM_RE.search("attacker@evil.ru")
        assert m is not None
        assert m.group(1) == "evil.ru"


# ─── EmailParser tests ────────────────────────────────────────────────────────

class TestEmailParser:
    def test_parses_from_header(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        assert "paypa1-support.com" in ep.from_header
        os.unlink(path)

    def test_parses_from_domain(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        assert ep.from_domain == "paypa1-support.com"
        os.unlink(path)

    def test_parses_reply_to_domain(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        assert ep.reply_to_domain == "attacker.com"
        os.unlink(path)

    def test_parses_return_path_domain(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        assert ep.return_path_domain == "evil.ru"
        os.unlink(path)

    def test_parses_subject(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        assert "URGENT" in ep.subject
        os.unlink(path)

    def test_parses_auth_results(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        assert "spf=fail" in ep.auth_results.lower()
        os.unlink(path)

    def test_parses_body_text(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        assert "verify" in ep.full_body.lower()
        os.unlink(path)

    def test_parses_attachment(self):
        path = write_eml(ATTACHMENT_EML)
        ep = EmailParser(path)
        ep.parse()
        assert len(ep.attachments) == 1
        assert ep.attachments[0]["filename"] == "invoice.pdf.exe"
        os.unlink(path)

    def test_raises_on_missing_file(self):
        ep = EmailParser("/tmp/nonexistent_abc123.eml")
        with pytest.raises(FileNotFoundError):
            ep.parse()

    def test_raises_on_empty_file(self):
        tf = tempfile.NamedTemporaryFile(mode="w", suffix=".eml", delete=False)
        tf.close()
        ep = EmailParser(tf.name)
        with pytest.raises(ValueError, match="empty"):
            ep.parse()
        os.unlink(tf.name)

    def test_legit_email_from_domain(self):
        path = write_eml(LEGIT_EML)
        ep = EmailParser(path)
        ep.parse()
        assert ep.from_domain == "github.com"
        os.unlink(path)


# ─── PhishingAnalyzer tests ───────────────────────────────────────────────────

class TestAuthChecks:
    def test_spf_fail_adds_score(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.check_authentication()
        spf_findings = [f for f in az.findings if f[0] == "SPF" and f[2] > 0]
        assert len(spf_findings) > 0
        os.unlink(path)

    def test_dkim_none_adds_score(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.check_authentication()
        dkim_findings = [f for f in az.findings if f[0] == "DKIM" and f[2] > 0]
        assert len(dkim_findings) > 0
        os.unlink(path)

    def test_dmarc_fail_adds_score(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.check_authentication()
        dmarc_findings = [f for f in az.findings if f[0] == "DMARC" and f[2] > 0]
        assert len(dmarc_findings) > 0
        os.unlink(path)

    def test_legit_auth_no_score(self):
        path = write_eml(LEGIT_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.check_authentication()
        auth_score = sum(f[2] for f in az.findings if f[0] in ("SPF","DKIM","DMARC"))
        assert auth_score == 0
        os.unlink(path)


class TestSpoofingChecks:
    def test_reply_to_mismatch_detected(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.check_spoofing()
        spoof = [f for f in az.findings if f[0] == "SPOOFING" and "Reply-To" in f[1]]
        assert len(spoof) > 0
        os.unlink(path)

    def test_return_path_mismatch_detected(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.check_spoofing()
        spoof = [f for f in az.findings if f[0] == "SPOOFING" and "Return-Path" in f[1]]
        assert len(spoof) > 0
        os.unlink(path)

    def test_legit_no_spoofing(self):
        path = write_eml(LEGIT_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.check_spoofing()
        assert not any(f[0] == "SPOOFING" for f in az.findings)
        os.unlink(path)


class TestURLExtraction:
    def test_extracts_http_url(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        urls = az.extract_urls()
        assert any("paypa1-secure.xyz" in u for u in urls)
        os.unlink(path)

    def test_extracts_ip_url(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        urls = az.extract_urls()
        assert any("185.220.101.47" in u for u in urls)
        os.unlink(path)

    def test_extracts_shortener(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        urls = az.extract_urls()
        assert any("bit.ly" in u for u in urls)
        os.unlink(path)

    def test_legit_urls_extracted(self):
        path = write_eml(LEGIT_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        urls = az.extract_urls()
        assert any("github.com" in u for u in urls)
        os.unlink(path)

    def test_no_urls_returns_empty(self):
        eml = NO_AUTH_EML.replace("https://example.com for more info.", "nothing here")
        path = write_eml(eml)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        # Should not raise even with no URLs
        urls = az.extract_urls()
        assert isinstance(urls, list)
        os.unlink(path)


class TestURLChecks:
    def test_ip_url_flagged(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.extract_urls()
        az.check_urls()
        ip_flags = [f for f in az.findings if f[0] == "URL" and "IP-based" in f[1]]
        assert len(ip_flags) > 0
        os.unlink(path)

    def test_shortener_flagged(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.extract_urls()
        az.check_urls()
        short_flags = [f for f in az.findings if f[0] == "URL" and "shortener" in f[1].lower()]
        assert len(short_flags) > 0
        os.unlink(path)

    def test_lookalike_flagged(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.extract_urls()
        az.check_urls()
        lookalike = [f for f in az.findings if f[0] == "URL" and "lookalike" in f[1].lower()]
        assert len(lookalike) > 0
        os.unlink(path)


class TestLanguageChecks:
    def test_phishing_keywords_detected(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.check_phishing_language()
        lang = [f for f in az.findings if f[0] == "LANGUAGE"]
        assert len(lang) > 0
        assert lang[0][2] > 0
        os.unlink(path)

    def test_legit_no_language_flags(self):
        path = write_eml(LEGIT_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.check_phishing_language()
        lang = [f for f in az.findings if f[0] == "LANGUAGE"]
        assert len(lang) == 0
        os.unlink(path)


class TestAttachmentChecks:
    def test_double_extension_flagged(self):
        path = write_eml(ATTACHMENT_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.check_attachments()
        attach = [f for f in az.findings if f[0] == "ATTACHMENT"]
        assert len(attach) > 0
        assert "invoice.pdf.exe" in attach[0][1]
        os.unlink(path)

    def test_no_attachments_no_score(self):
        path = write_eml(LEGIT_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.check_attachments()
        attach = [f for f in az.findings if f[0] == "ATTACHMENT"]
        assert len(attach) == 0
        os.unlink(path)


class TestVerdict:
    def test_phishing_email_scores_high(self):
        path = write_eml(PHISHING_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.run_all(skip_vt=True)
        assert az.score >= VERDICT_PHISHING
        assert "PHISHING" in az.verdict_short()
        os.unlink(path)

    def test_legit_email_scores_low(self):
        path = write_eml(LEGIT_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.run_all(skip_vt=True)
        assert az.score < VERDICT_SUSPICIOUS
        assert "LEGITIMATE" in az.verdict_short()
        os.unlink(path)

    def test_attachment_email_flagged(self):
        path = write_eml(ATTACHMENT_EML)
        ep = EmailParser(path)
        ep.parse()
        az = PhishingAnalyzer(ep)
        az.run_all(skip_vt=True)
        assert az.score >= VERDICT_SUSPICIOUS
        os.unlink(path)
