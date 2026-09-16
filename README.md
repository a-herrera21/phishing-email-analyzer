# 🎣 Phishing Email Analyzer

A command-line security tool that performs multi-signal phishing analysis on `.eml` files — the kind of triage work a SOC Tier-1 analyst does dozens of times per day, automated into a single tool.

Analyzes email authentication headers (SPF/DKIM/DMARC), detects sender spoofing, extracts and scores URLs for suspicious patterns, checks against VirusTotal, scans for phishing language, and flags dangerous attachments — then delivers a clear verdict with a full breakdown of every triggered signal.

---

## 🎯 Why This Matters for a SOC Analyst

Phishing triage is one of the most common Tier-1 SOC tasks. Analysts manually review reported emails, check headers, look up URLs, and make a call: phishing or legitimate? This tool automates that workflow:

| Manual Task | This Tool |
|---|---|
| Open email headers, read SPF/DKIM/DMARC | ✅ Automated — flags failures instantly |
| Compare From vs Reply-To vs Return-Path | ✅ Detects mismatches and spoofing |
| Copy URLs, check for lookalikes | ✅ Regex extraction + typosquatting detection |
| Submit URLs to VirusTotal | ✅ API integration with scoring |
| Read body for urgency/threat language | ✅ 17-pattern heuristic scan |
| Check attachments for double extensions | ✅ Flags .pdf.exe etc. |
| Write up findings | ✅ Auto-generates markdown report |

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.11 | Core language |
| `email` (stdlib) | `.eml` file parsing |
| `re` (stdlib) | URL extraction, domain parsing, language patterns |
| `urllib.parse` | URL domain decomposition |
| `requests` | VirusTotal REST API calls |
| `argparse` | CLI interface |
| `pytest` | 41 unit tests |

---

## 📁 Project Structure

```
phishing-email-analyzer/
├── analyze.py               # Main CLI tool
├── requirements.txt         # Python dependencies
├── .env.example             # API key template
├── samples/
│   ├── phishing_paypal.eml  # Spoofed PayPal — SPF/DMARC fail, lookalike domain, IP URL
│   ├── phishing_office365.eml # Spoofed Microsoft — double-extension attachment
│   ├── phishing_bank.eml    # Spoofed Chase — no auth records, urgency language
│   ├── legit_github.eml     # Legitimate GitHub notification
│   └── legit_aws.eml        # Legitimate AWS billing email
├── tests/
│   ├── __init__.py
│   └── test_analyze.py      # 41 unit tests
└── README.md
```

---

## ⚡ Quick Start

### 1. Clone & install

```bash
git clone https://github.com/a-herrera21/phishing-email-analyzer.git
cd phishing-email-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Set up API keys (optional but recommended)

```bash
cp .env.example .env
# Edit .env and add:
# VIRUSTOTAL_API_KEY=your-key  (free at https://virustotal.com)
source .env
```

### 3. Analyze an email

```bash
python analyze.py --file samples/phishing_paypal.eml
python analyze.py --file suspicious.eml --no-vt         # skip VirusTotal
python analyze.py --file email.eml --output report.md   # custom output path
```

---

## 🖥️ Real Output Examples

### Phishing Email (`phishing_paypal.eml`)

```
============================================================
  Phishing Email Analyzer v1.0.0
============================================================

[1/5] Parsing email: samples/phishing_paypal.eml
      From:    "PayPal Security Team" <security@paypa1-support.com>
      Subject: URGENT: Your PayPal account has been limited - Action required within 24 hours
      Body length: 907 chars | Attachments: 0

[2/5] Checking authentication (SPF/DKIM/DMARC)...
      ⚠️  SPF check FAILED — sending server not authorized for this domain
      ⚠️  DKIM=none — email was not signed
      ⚠️  DMARC check FAILED — email does not align with domain policy

[3/5] Checking for spoofing / header mismatches...
      🚨 Return-Path domain (smtp-bulk-mailer-99.ru) differs from From domain (paypa1-support.com)
      🚨 Display name claims to be 'Paypal' but sending domain is 'paypa1-support.com' not 'paypal.com'

[4/5] Extracting and analyzing URLs...
      Found 3 URL(s)
      ⚠️  Lookalike domain impersonating 'paypal': paypa1-secure-login.xyz
      ⚠️  URL shortener detected (hides real destination): http://tinyurl.com/paypal-verify-account
      ⚠️  IP-based URL (bypasses domain filtering): http://185.220.101.47/paypal/login.php

============================================================
  VERDICT: 🚨 LIKELY PHISHING
  RISK SCORE: 203
============================================================

Triggered signals:
  [SPF]      +20  SPF check FAILED
  [DKIM]     +10  DKIM=none — email was not signed
  [DMARC]    +20  DMARC check FAILED
  [SPOOFING] +20  Return-Path domain mismatch
  [SPOOFING] +15  Display name impersonation
  [URL]      +20  Lookalike domain impersonating 'paypal'
  [URL]      +15  URL shortener detected
  [URL]      +25  IP-based URL
  [LANGUAGE] +40  11 phishing language patterns matched
```

---

### Legitimate Email (`legit_github.eml`)

```
============================================================
  Phishing Email Analyzer v1.0.0
============================================================

[1/5] Parsing email: samples/legit_github.eml
      From:    "GitHub" <noreply@github.com>
      Subject: [GitHub] A third-party OAuth application has been added to your account
      Body length: 863 chars | Attachments: 0

[2/5] Checking authentication (SPF/DKIM/DMARC)...
      ✓ Authentication looks clean

[3/5] Checking for spoofing / header mismatches...
      ✓ No spoofing detected

[4/5] Extracting and analyzing URLs...
      Found 3 URL(s)

============================================================
  VERDICT: ✅ LIKELY LEGITIMATE
  RISK SCORE: 8
============================================================

Triggered signals:
  [LANGUAGE] +8  'immediately' matched (low weight, single hit)
```

---

## 📊 Detection Signals & Scoring

| Signal | Points | Why It Matters |
|---|---|---|
| SPF fail | +20 | Sending server not authorized for domain |
| SPF softfail | +10 | Domain discourages this sender |
| DKIM fail | +20 | Email was tampered or forged |
| DKIM none | +10 | Email unsigned — authentication gap |
| DMARC fail | +20 | Email violates domain's published policy |
| Reply-To mismatch | +25 | Replies go to attacker, not sender |
| Return-Path mismatch | +20 | Bounce goes to different domain |
| Display name spoofing | +15 | Claims to be PayPal but isn't |
| Lookalike domain | +20 | Typosquatting (paypa1 vs paypal) |
| IP-based URL | +25 | Hides domain, bypasses filters |
| URL shortener | +15 | Obscures real destination |
| VirusTotal malicious | +35 | Community-confirmed malicious URL |
| Phishing language | +8/hit (max 40) | Urgency, threats, "verify account" |
| Suspicious attachment | +30 | Double extension (.pdf.exe) or executable |

**Verdict thresholds:**
- `< 25` → ✅ LIKELY LEGITIMATE
- `25–59` → ⚠️ SUSPICIOUS
- `≥ 60` → 🚨 LIKELY PHISHING

---

## ✅ Running Tests

```bash
python -m pytest tests/ -v
```

Expected: `41 passed`

---

## 🔑 API Keys

| Key | Required? | Source |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | Optional | [virustotal.com](https://virustotal.com) — free tier, 4 req/min |

Without a VirusTotal key the tool runs in offline mode — all other signals still work.

---

## 🗺️ Roadmap

- [ ] Support `.msg` (Outlook) format
- [ ] Bulk analysis: `analyze.py --dir /path/to/emails/`
- [ ] WHOIS lookup for newly registered domains
- [ ] HTML report output

---

## 📄 License

MIT
