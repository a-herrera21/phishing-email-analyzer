# Phishing Email Analyzer
## Complete User Guide

---

## What This Tool Does

This tool reads email files (`.eml` format) and runs them through a multi-signal phishing detection engine. In plain English:

1. **Parses the email** — reads headers, body, and attachments from the file
2. **Checks email authentication** — looks at SPF, DKIM, and DMARC results to see if the email actually came from who it claims to be from
3. **Detects spoofing** — compares the "From" address against the "Reply-To" and "Return-Path" headers to catch cases where replies would go to an attacker
4. **Extracts all URLs** — pulls every link out of the email body using regex
5. **Analyzes each URL** — flags lookalike/typosquatting domains (paypa1 instead of paypal), IP-based URLs, URL shorteners, and suspicious TLDs
6. **Checks VirusTotal** — looks up URLs against a global threat database (requires a free API key)
7. **Scans for phishing language** — checks the subject and body for 17 patterns: urgency, threats, "verify your account," time pressure, etc.
8. **Inspects attachments** — flags dangerous file types and double-extension attacks like `.pdf.exe`
9. **Delivers a scored verdict** — every triggered signal adds points to a risk score, and the final verdict is: LIKELY PHISHING / SUSPICIOUS / LIKELY LEGITIMATE

---

## How the Scoring Works

Every signal that fires adds points to a risk score. Here's the full breakdown:

| Signal | Points | What It Means |
|--------|--------|---------------|
| SPF fail | +20 | The sending server is not authorized to send email for that domain |
| SPF softfail | +10 | The domain owner discourages but doesn't block this sender |
| DKIM fail | +20 | The email's cryptographic signature is broken or missing — it may have been tampered |
| DKIM none | +10 | Email was never signed — no authentication trail |
| DMARC fail | +20 | The email violates the domain's published authentication policy |
| Reply-To mismatch | +25 | If you hit Reply, your response goes to a different domain than the sender — classic attacker trick |
| Return-Path mismatch | +20 | Bounce messages go to a different domain |
| Display name spoofing | +15 | Sender claims to be "PayPal" but the domain isn't paypal.com |
| Lookalike domain | +20 | Typosquatting detected (paypa1.xyz, micros0ft-support.net) |
| IP-based URL | +25 | Link goes to a raw IP address instead of a domain — bypasses domain filters |
| URL shortener | +15 | Hides the real destination (bit.ly, tinyurl.com, etc.) |
| VirusTotal malicious | +35 | Community-confirmed malicious URL |
| VirusTotal suspicious | +20 | Flagged as suspicious by some engines |
| Phishing language | +8 per hit, max +40 | Urgency words, threats, "verify account," "click here," etc. |
| Suspicious attachment | +30 | Double extension (.pdf.exe) or executable file type |

**Final verdict thresholds:**
- Score **under 25** → ✅ LIKELY LEGITIMATE
- Score **25–59** → ⚠️ SUSPICIOUS
- Score **60 or above** → 🚨 LIKELY PHISHING

---

## Where The Tool Lives

On your Linux server (`srv1716560`), logged in as `mando`:

```
~/projects/phishing-email-analyzer/
```

Full path: `/home/mando/projects/phishing-email-analyzer/`

---

## Files In The Project

```
phishing-email-analyzer/
├── analyze.py               ← The main tool (run this)
├── requirements.txt         ← Python package list
├── .env.example             ← API key template
├── .env                     ← Your actual API keys (private, not on GitHub)
├── venv/                    ← Python virtual environment (pre-installed)
├── samples/
│   ├── phishing_paypal.eml      ← Spoofed PayPal with fake domain, IP URL, SPF/DMARC fail
│   ├── phishing_office365.eml   ← Spoofed Microsoft with double-extension .pdf.exe attachment
│   ├── phishing_bank.eml        ← Spoofed Chase bank with urgency language, no auth records
│   ├── legit_github.eml         ← Real-style GitHub notification (passes all checks)
│   └── legit_aws.eml            ← Real-style AWS billing email (passes all checks)
├── tests/
│   └── test_analyze.py      ← 41 unit tests
└── README.md                ← Quick reference
```

---

## First-Time Setup (Already Done For You)

Everything below was already completed. This is here for reference only.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Step 1 — SSH Into Your Server

```bash
ssh mando@<your-server-ip>
```

---

## Step 2 — Navigate To The Tool

```bash
cd ~/projects/phishing-email-analyzer
```

---

## Step 3 — Activate The Virtual Environment

Do this every time you open a new terminal session:

```bash
source venv/bin/activate
```

You'll know it worked when you see `(venv)` at the start of your terminal prompt.

---

## Step 4 — Load Your API Keys

```bash
source .env
```

---

## Step 5 — Run The Tool

### Analyze a sample phishing email:
```bash
python analyze.py --file samples/phishing_paypal.eml
```

### Analyze a legitimate email:
```bash
python analyze.py --file samples/legit_github.eml
```

### Analyze your own email file:
```bash
python analyze.py --file /path/to/suspicious.eml
```

### Skip VirusTotal (faster, no key needed):
```bash
python analyze.py --file samples/phishing_paypal.eml --no-vt
```

### Save report to a specific file:
```bash
python analyze.py --file suspicious.eml --output my_report.md
```

### Full example with all options:
```bash
python analyze.py --file samples/phishing_paypal.eml --output phishing_report.md --no-vt
```

---

## What The Output Looks Like

### Phishing email example:

```
============================================================
  Phishing Email Analyzer v1.0.0
============================================================

[1/5] Parsing email: samples/phishing_paypal.eml
      From:    "PayPal Security Team" <security@paypa1-support.com>
      Subject: URGENT: Your PayPal account has been limited
      Body length: 907 chars | Attachments: 0

[2/5] Checking authentication (SPF/DKIM/DMARC)...
      ⚠️  SPF check FAILED — sending server not authorized for this domain
      ⚠️  DKIM=none — email was not signed
      ⚠️  DMARC check FAILED — email does not align with domain policy

[3/5] Checking for spoofing / header mismatches...
      🚨 Return-Path domain (smtp-bulk-mailer-99.ru) differs from From domain
      🚨 Display name claims to be 'Paypal' but sending domain is 'paypa1-support.com'

[4/5] Extracting and analyzing URLs...
      Found 3 URL(s)
      ⚠️  Lookalike domain impersonating 'paypal': paypa1-secure-login.xyz
      ⚠️  URL shortener detected: http://tinyurl.com/paypal-verify-account
      ⚠️  IP-based URL (bypasses domain filtering): http://185.220.101.47/paypal/login.php

[5/5] Computing verdict...

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
  [URL]      +10  Suspicious TLD '.xyz'
  [URL]      +20  Lookalike domain impersonating 'paypal'
  [URL]      +15  URL shortener detected
  [URL]      +25  IP-based URL
  [LANGUAGE] +40  11 phishing language patterns matched

✅ Report saved to: report_phishing_paypal_20260916.md
```

### Legitimate email example:

```
============================================================
  VERDICT: ✅ LIKELY LEGITIMATE
  RISK SCORE: 8
============================================================

Triggered signals:
  [LANGUAGE] +8  'immediately' matched (single low-weight hit)
```

---

## How To Get Your Own .eml Files

`.eml` is a standard email format. Here's how to export emails from common clients:

**Gmail:**
1. Open the email
2. Click the three-dot menu (top right of email)
3. Click "Download message"
4. Saves as a `.eml` file

**Outlook:**
1. Open the email
2. File → Save As
3. Choose "Outlook Message Format" or drag the email to your desktop

**Apple Mail:**
1. Select the email
2. File → Save As
3. Choose "Raw Message Source"

---

## Enabling VirusTotal (Optional)

VirusTotal checks your extracted URLs against 90+ security engines.

**Get a free key:**
1. Go to https://virustotal.com
2. Create a free account
3. Click your profile picture → API key
4. Copy the key

**Add it to the tool:**
```bash
nano ~/projects/phishing-email-analyzer/.env
```
Add this line:
```
VIRUSTOTAL_API_KEY=your-key-here
```
Save with `Ctrl+O`, exit with `Ctrl+X`, then:
```bash
source .env
```

**Free tier limits:** 4 requests/minute, 500/day — plenty for personal use.

---

## Running Against a Real Suspicious Email

1. Export the email as `.eml` from your email client (see above)
2. Transfer it to your server:
   ```bash
   scp suspicious.eml mando@<your-server-ip>:~/projects/phishing-email-analyzer/
   ```
3. Run the analysis:
   ```bash
   cd ~/projects/phishing-email-analyzer
   source venv/bin/activate
   source .env
   python analyze.py --file suspicious.eml
   ```
4. Check the generated `report_*.md` file for the full breakdown

---

## Running The Unit Tests

To verify the tool is working correctly:

```bash
cd ~/projects/phishing-email-analyzer
source venv/bin/activate
python -m pytest tests/ -v
```

Expected result: `41 passed`

---

## Understanding The Report File

Every run saves a `.md` report file automatically (auto-named with timestamp unless you use `--output`). It contains:

- **Email metadata** — From, Subject, Reply-To, Return-Path, Date
- **Verdict and score** at the top
- **Authentication section** — SPF/DKIM/DMARC results with pass/fail
- **Spoofing section** — header mismatch findings
- **URL section** — all extracted URLs listed, then flagged ones explained
- **VirusTotal section** — per-URL engine results
- **Language section** — which phishing patterns matched
- **Attachment section** — filenames, types, and any flags
- **Score breakdown table** — every triggered signal with its point value

---

## Troubleshooting

### "command not found: python"
Activate the venv first:
```bash
source venv/bin/activate
```

### "ModuleNotFoundError: No module named 'requests'"
Reinstall dependencies:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### VirusTotal shows "skipped — no API key"
Your `.env` file isn't loaded or the key isn't set:
```bash
source .env
```
Or pass the key directly:
```bash
python analyze.py --file suspicious.eml --vt-key YOUR_KEY_HERE
```

### "Email file not found"
Check your path — use the full path if needed:
```bash
python analyze.py --file /home/mando/projects/phishing-email-analyzer/samples/phishing_paypal.eml
```

### "Email file is empty"
The `.eml` file is empty or didn't export correctly. Re-export from your email client.

---

## GitHub Repository

All source code is publicly available at:

**https://github.com/a-herrera21/phishing-email-analyzer**

To pull the latest updates:
```bash
cd ~/projects/phishing-email-analyzer
git pull
```

---

## Quick Reference Card

```bash
# Every session — do these first:
ssh mando@<your-server-ip>
cd ~/projects/phishing-email-analyzer
source venv/bin/activate
source .env

# Analyze a phishing sample:
python analyze.py --file samples/phishing_paypal.eml

# Analyze a legit sample:
python analyze.py --file samples/legit_github.eml

# Analyze your own email:
python analyze.py --file suspicious.eml

# Skip VirusTotal (faster):
python analyze.py --file suspicious.eml --no-vt

# Save to specific file:
python analyze.py --file suspicious.eml --output report.md

# Run all tests:
python -m pytest tests/ -v

# Check what's in samples folder:
ls samples/
```

---

## What Each Sample Email Tests

| File | Type | Key Signals |
|------|------|-------------|
| `phishing_paypal.eml` | 🔴 Phishing | SPF/DMARC fail, lookalike domain, IP URL, URL shortener, 11 phishing phrases |
| `phishing_office365.eml` | 🔴 Phishing | SPF softfail, DKIM fail, .pdf.exe attachment, Reply-To mismatch |
| `phishing_bank.eml` | 🔴 Phishing | No auth records, urgency language, suspicious domain keywords |
| `legit_github.eml` | ✅ Legit | SPF/DKIM/DMARC all pass, no header mismatches, clean URLs |
| `legit_aws.eml` | ✅ Legit | SPF/DKIM/DMARC all pass, legitimate amazon.com URLs |

---

*Phishing Email Analyzer v1.0.0 — Built for Armando Herrera's cybersecurity portfolio*
*GitHub: github.com/a-herrera21/phishing-email-analyzer*
