# Phishing Email Analyzer

A command-line tool that analyzes .eml files and flags whether an email is likely phishing. This automates the same triage steps a SOC Tier-1 analyst does by hand when a user reports a suspicious email: check the authentication headers, look for sender spoofing, check the links, scan the language, check attachments, and give a verdict.

## Why I built this

Phishing triage is one of the most common tasks in an entry-level SOC role. Instead of just reading about SPF/DKIM/DMARC, I wanted to build something that actually parses real headers and makes a call on real sample emails, so I understand what's happening under the hood instead of just knowing the acronyms.

## What it checks

- **Authentication headers** - SPF, DKIM, DMARC pass/fail
- **Spoofing** - compares From, Reply-To, and Return-Path domains for mismatches, and checks if the display name is impersonating a brand
- **URLs** - extracts every link in the body, flags lookalike/typosquatted domains, IP-based URLs, URL shorteners, suspicious TLDs, and optionally checks them against VirusTotal
- **Language** - scans body text for urgency/threat phrasing common in phishing ("act now," "account limited," "verify your account")
- **Attachments** - flags double extensions (invoice.pdf.exe) and risky file types

Each check adds points to a risk score. Under 25 = likely legitimate, 25-59 = suspicious, 60+ = likely phishing. The tool prints exactly which signals fired and why, and saves a report as markdown.

## Project structure

```
phishing-email-analyzer/
├── analyze.py               # main CLI tool
├── requirements.txt
├── .env.example              # VirusTotal key template
├── samples/                  # test emails, 3 phishing + 2 legit
└── tests/
    └── test_analyze.py       # 41 unit tests
```

## Running it

```bash
git clone https://github.com/a-herrera21/phishing-email-analyzer.git
cd phishing-email-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

VirusTotal is optional. Free tier key from virustotal.com, put it in `.env`:

```bash
cp .env.example .env
# add VIRUSTOTAL_API_KEY=your-key
```

Then run it:

```bash
python analyze.py --file samples/phishing_paypal.eml
python analyze.py --file samples/legit_github.eml --no-vt   # skip VirusTotal
```

## Real output

Ran against a spoofed PayPal sample:

```
[2/5] Checking authentication (SPF/DKIM/DMARC)...
      SPF check FAILED - sending server not authorized for this domain
      DKIM=none - email was not signed
      DMARC check FAILED - email does not align with domain policy

[3/5] Checking for spoofing / header mismatches...
      Return-Path domain (smtp-bulk-mailer-99.ru) differs from From domain (paypa1-support.com)
      Display name claims to be 'Paypal' but sending domain is 'paypa1-support.com' not 'paypal.com'

[4/5] Extracting and analyzing URLs...
      Found 3 URL(s)
      Lookalike domain impersonating 'paypal': paypa1-secure-login.xyz
      URL shortener detected: http://tinyurl.com/paypal-verify-account
      IP-based URL: http://185.220.101.47/paypal/login.php

VERDICT: LIKELY PHISHING
RISK SCORE: 203
```

Same tool against a real GitHub notification email:

```
[2/5] Checking authentication (SPF/DKIM/DMARC)...
      Authentication looks clean

[3/5] Checking for spoofing / header mismatches...
      No spoofing detected

VERDICT: LIKELY LEGITIMATE
RISK SCORE: 8
```

## Detection signals and scoring

| Signal | Points | Why it matters |
|---|---|---|
| SPF fail | +20 | Sending server not authorized for domain |
| SPF softfail | +10 | Domain discourages this sender |
| DKIM fail | +20 | Email was tampered or forged |
| DKIM none | +10 | Email unsigned, no way to verify integrity |
| DMARC fail | +20 | Violates domain's published policy |
| Reply-To mismatch | +25 | Replies go to the attacker, not the real sender |
| Return-Path mismatch | +20 | Bounce address doesn't match sender domain |
| Display name spoofing | +15 | Claims to be a known brand but domain doesn't match |
| Lookalike domain | +20 | Typosquatting, e.g. paypa1 vs paypal |
| IP-based URL | +25 | Hides the real domain, bypasses filtering |
| URL shortener | +15 | Hides the real destination |
| VirusTotal malicious hit | +35 | Community-confirmed malicious |
| Phishing language | up to +40 | Urgency, threats, "verify your account" style phrasing |
| Suspicious attachment | +30 | Double extension or executable type |

## Tests

```bash
python -m pytest tests/ -v
```

41 tests, all passing, covering header parsing and URL extraction.

## What I'd add next

- .msg (Outlook) format support
- Bulk mode to scan a whole folder of emails at once
- WHOIS lookup for newly registered domains, since phishing domains are often only days old

## License

MIT
