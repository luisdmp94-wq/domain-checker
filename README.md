[README.md](https://github.com/user-attachments/files/29944466/README.md)
# domain-checker
Security reconnaissance tool for domains.

## Features
- IP resolution
- Security headers analysis
- Subdomain discovery# domain-checker 🔍

Security reconnaissance tool for domains — automated recon for bug bounty and penetration testing.

Built by [@vaalsec](https://hackerone.com/vaalsec) as part of the **De Cero a Hacker** project.

---

## Features

25+ security modules covering the full recon pipeline:

**Infrastructure**
- IP resolution
- Open port scanning (Nmap)
- WAF detection (wafw00f)
- SSL/TLS analysis (expiry, issuer, validity)
- DNS records (MX, NS, SPF, DMARC, DKIM)
- Server info disclosure

**Discovery**
- Subdomain enumeration
- Subdomain headers analysis
- Subdomain takeover detection
- Robots.txt & sitemap parsing
- Sensitive file detection

**Web Security**
- Security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
- HTTP redirect verification (HTTP → HTTPS)
- HTTP methods testing (PUT, DELETE, TRACE, PATCH)
- Cookie security flags (HttpOnly, Secure, SameSite)
- CORS misconfiguration detection
- CSRF protection analysis
- Open redirect detection (with final destination validation)
- Source code analysis (comments, tokens, endpoints)

**API & Endpoints**
- Exposed paths detection with content signature validation (Prometheus, Git, .env, Swagger, GraphQL, dashboards)
- API endpoint enumeration (unauthenticated access detection)
- JavaScript file scanning (AWS keys, GCP keys, GitHub tokens, JWTs, internal IPs)

**Threat Intelligence**
- CVE lookup for detected technologies
- Email spoofing vulnerability check (SPF, DMARC, DKIM)
- Shodan/HackerTarget integration

**Reporting**
- Risk score (0-100) with severity breakdown
- JSON report
- Markdown report
- HTML report

---

## Usage

```bash
python domain-checker.py <domain>
```

**Example:**
```bash
python domain-checker.py example.com
```

Generates three report files:
```
report_example.com_20260712_120000.json
report_example.com_20260712_120000.md
report_example.com_20260712_120000.html
```

---

## Requirements

```bash
pip install requests dnspython builtwith python-nmap wafw00f websocket-client
```

**External tools:**
- Nmap
- wafw00f

---

## Stack

- Python 3.x
- Windows / Ubuntu (VirtualBox)
- Burp Suite (manual follow-up)

---

## Disclaimer

This tool is intended for authorized security research and bug bounty programs only. Always ensure you have explicit permission before scanning any target. The author is not responsible for any misuse.

---

## Author

Luis | [@vaalsec](https://hackerone.com/vaalsec) | HackerOne Bug Bounty Researcher  
Part of the **De Cero a Hacker** journey 🚀

- JSON report generation

## Usage
python domain-checker.py <domain>
