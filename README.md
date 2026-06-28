# 🔍 WebVulnScan

**Advanced Web Vulnerability Scanner** — Automated detection of XSS, SQL Injection, CSRF, and security header misconfigurations.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![CI](https://github.com/yourusername/web-vuln-scanner/actions/workflows/ci.yml/badge.svg)

> ⚠️ **For authorized security testing only.** Only scan targets you own or have explicit written permission to test.

---

## Features

| Module | Techniques |
|--------|-----------|
| **XSS** | Reflected, context-aware payloads, WAF bypass variants |
| **SQLi** | Error-based, Boolean-based blind, Time-based blind |
| **CSRF** | Missing token, weak token, server-side validation bypass |
| **Headers** | HSTS, CSP, X-Frame-Options, CORS, information disclosure |

- 🕷️ Built-in crawler — discovers pages and forms automatically  
- 📄 Three report formats: **terminal**, **JSON**, **HTML**  
- 🔌 Proxy support (Burp Suite, OWASP ZAP)  
- 🍪 Cookie & custom header injection for authenticated scans  
- ⚡ Configurable depth, timeout, and scan modules  
- 🤖 GitHub Actions CI with multi-Python-version matrix  

---

## Installation

```bash
git clone https://github.com/yourusername/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install -e .
```

---

## Usage

### Basic scan

```bash
python scan.py -u https://target.example.com
```

### Full options

```bash
python scan.py -u https://target.example.com \
  --depth 3 \
  --proxy http://127.0.0.1:8080 \
  --cookies "session=abc123; user=admin" \
  --waf-bypass \
  --output-json report.json \
  --output-html report.html \
  -v
```

### Skip specific modules

```bash
python scan.py -u https://target.example.com --no-sqli --no-headers
```

### All flags

| Flag | Description |
|------|-------------|
| `-u`, `--url` | Target URL (required) |
| `-d`, `--depth` | Crawl depth (default: 2) |
| `--proxy` | HTTP proxy URL |
| `--cookies` | Cookie string |
| `--headers` | Extra headers as JSON |
| `--timeout` | Request timeout in seconds |
| `--no-xss` | Skip XSS scanning |
| `--no-sqli` | Skip SQLi scanning |
| `--no-csrf` | Skip CSRF scanning |
| `--no-headers` | Skip headers scanning |
| `--waf-bypass` | Add WAF bypass XSS payloads |
| `--output-json` | Save JSON report |
| `--output-html` | Save HTML report |
| `-v` | Verbose logging |

---

## Example Output

```
======================================================================
  WebVulnScan Report — https://target.example.com
  2025-01-15 14:32:00
======================================================================
  Total findings: 4
    Critical: 1
    High: 2
    Medium: 1
======================================================================

[1] Critical — SQLi: Error-Based
     URL:       https://target.example.com/search
     Parameter: q
     Method:    GET
     Payload:   '
     Evidence:  DB error: 'You have an error in your SQL syntax'

[2] High — XSS: Reflected
     URL:       https://target.example.com/search
     Parameter: q
     Method:    GET
     Payload:   <script>alert(1)</script>
     Evidence:  Payload reflected unencoded in response body
...
```

---

## Project Structure

```
web-vuln-scanner/
├── scan.py                     # CLI entry point
├── webvulnscan/
│   ├── scanners/
│   │   ├── xss.py              # XSS detection
│   │   ├── sqli.py             # SQL Injection detection
│   │   ├── csrf.py             # CSRF detection
│   │   └── headers.py          # Security headers
│   ├── utils/
│   │   ├── session.py          # HTTP session manager
│   │   └── crawler.py          # URL & form crawler
│   └── reporters/
│       └── report.py           # Terminal / JSON / HTML reports
├── tests/
│   └── test_scanners.py        # Unit tests
├── .github/workflows/ci.yml    # GitHub Actions
├── requirements.txt
└── setup.py
```

---

## Running Tests

```bash
pytest tests/ -v --cov=webvulnscan
```

---

## Extending

Add a new scanner by creating `webvulnscan/scanners/yourscanner.py` with a class that implements:

```python
class YourScanner:
    def __init__(self, session): ...
    def run(self, urls, forms) -> List[Dict]: ...
```

Then import and add it in `scan.py`.

---

## Roadmap

- [ ] Open Redirect detection  
- [ ] Directory/file brute-forcing  
- [ ] Subdomain enumeration  
- [ ] SSRF detection  
- [ ] Async scanning with `httpx`/`asyncio`  
- [ ] Burp Suite extension wrapper  
- [ ] CVE-based fingerprinting  

---

## Legal

This tool is for **educational and authorized penetration testing purposes only**.  
Unauthorized scanning is illegal. The author assumes no responsibility for misuse.

---

## License

MIT © 2025 Mohamed baalla
