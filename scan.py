#!/usr/bin/env python3
"""
WebVulnScan - Advanced Web Vulnerability Scanner
Usage: python scan.py -u <URL> [options]
"""

import argparse
import logging
import sys
from webvulnscan.utils.session import SessionManager
from webvulnscan.utils.crawler import Crawler
from webvulnscan.scanners.xss import XSSScanner
from webvulnscan.scanners.sqli import SQLiScanner
from webvulnscan.scanners.csrf import CSRFScanner
from webvulnscan.scanners.headers import HeadersScanner
from webvulnscan.reporters.report import print_terminal, save_json, save_html


BANNER = r"""
 __        __   _  __     ___     _        ____
 \ \      / /__| |_\ \   / / |   | |_ _  / ___|  ___ __ _ _ __
  \ \ /\ / / _ \ '_ \ \ / /| |   | __| \ \___ \ / __/ _` | '_ \
   \ V  V /  __/ |_) \ V / | |___| |_|  \___) | (_| (_| | | | |
    \_/\_/ \___|_.__/ \_/  |_____|\___|_/ |____/ \___\__,_|_| |_|

  Web Vulnerability Scanner v1.0.0 — XSS · SQLi · CSRF · Headers
  For authorized security testing only.
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="WebVulnScan — Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--cookies", help="Cookies string (e.g. 'session=abc; token=xyz')")
    parser.add_argument("--headers", help="Extra headers as JSON string")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--no-xss", action="store_true", help="Skip XSS scanning")
    parser.add_argument("--no-sqli", action="store_true", help="Skip SQLi scanning")
    parser.add_argument("--no-csrf", action="store_true", help="Skip CSRF scanning")
    parser.add_argument("--no-headers", action="store_true", help="Skip headers scanning")
    parser.add_argument("--waf-bypass", action="store_true", help="Include WAF bypass XSS payloads")
    parser.add_argument("--output-json", help="Save JSON report to file")
    parser.add_argument("--output-html", help="Save HTML report to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    return parser.parse_args()


def parse_cookies(cookie_str: str) -> dict:
    result = {}
    for part in cookie_str.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            result[k.strip()] = v.strip()
    return result


def parse_headers(header_str: str) -> dict:
    import json
    try:
        return json.loads(header_str)
    except Exception:
        print("[!] Could not parse --headers as JSON. Ignoring.")
        return {}


def main():
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    print(BANNER)
    print(f"[*] Target: {args.url}")
    print(f"[*] Crawl depth: {args.depth}")
    if args.proxy:
        print(f"[*] Proxy: {args.proxy}")
    print()

    # Build session
    cookies = parse_cookies(args.cookies) if args.cookies else None
    headers = parse_headers(args.headers) if args.headers else None

    session = SessionManager(
        proxy=args.proxy,
        timeout=args.timeout,
        cookies=cookies,
        headers=headers,
    )

    # Crawl
    print("[*] Crawling target...")
    crawler = Crawler(session, max_depth=args.depth, scope=args.url)
    urls, forms = crawler.crawl(args.url)
    print(f"[*] Discovered {len(urls)} URLs, {len(forms)} forms.\n")

    all_findings = []

    # Run scanners
    if not args.no_xss:
        print("[*] Running XSS scanner...")
        xss = XSSScanner(session, include_waf_bypass=args.waf_bypass)
        all_findings.extend(xss.run(urls, forms))

    if not args.no_sqli:
        print("[*] Running SQLi scanner...")
        sqli = SQLiScanner(session)
        all_findings.extend(sqli.run(urls, forms))

    if not args.no_csrf:
        print("[*] Running CSRF scanner...")
        csrf = CSRFScanner(session)
        all_findings.extend(csrf.run(urls, forms))

    if not args.no_headers:
        print("[*] Running Headers scanner...")
        hdrs = HeadersScanner(session)
        all_findings.extend(hdrs.run(urls, forms))

    session.close()

    # Report
    print_terminal(all_findings, args.url)

    if args.output_json:
        save_json(all_findings, args.url, args.output_json)

    if args.output_html:
        save_html(all_findings, args.url, args.output_html)

    # Exit code: non-zero if critical/high findings
    high_sev = [f for f in all_findings if f["severity"] in ("Critical", "High")]
    sys.exit(1 if high_sev else 0)


if __name__ == "__main__":
    main()
