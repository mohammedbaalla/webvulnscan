"""
Security Headers Scanner - Checks for missing or misconfigured HTTP security headers.
"""

from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": "Missing HSTS header. Site is vulnerable to protocol downgrade attacks.",
        "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Missing CSP header. No restriction on content sources, XSS risk elevated.",
        "recommendation": "Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Missing X-Frame-Options. Page may be embeddable in iframes (Clickjacking risk).",
        "recommendation": "X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "Missing X-Content-Type-Options. Browser may MIME-sniff responses.",
        "recommendation": "X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Missing Referrer-Policy. Referrer data may leak to third parties.",
        "recommendation": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Missing Permissions-Policy. Browser features unrestricted.",
        "recommendation": "Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
}

DANGEROUS_HEADERS = {
    "Server": "Exposes server software version",
    "X-Powered-By": "Exposes backend technology",
    "X-AspNet-Version": "Exposes ASP.NET version",
}


class HeadersScanner:
    """Scans HTTP response headers for security misconfigurations."""

    def __init__(self, session):
        self.session = session
        self.findings: List[Dict] = []

    def scan_url(self, url: str) -> List[Dict]:
        resp = self.session.get(url)
        if not resp:
            return []

        results = []
        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, meta in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                results.append({
                    "type": "Headers",
                    "subtype": f"Missing {header}",
                    "severity": meta["severity"],
                    "url": url,
                    "parameter": header,
                    "method": "GET",
                    "payload": None,
                    "evidence": meta["description"],
                    "recommendation": meta["recommendation"],
                })

        for header, description in DANGEROUS_HEADERS.items():
            if header.lower() in headers:
                results.append({
                    "type": "Headers",
                    "subtype": f"Information Disclosure ({header})",
                    "severity": "Info",
                    "url": url,
                    "parameter": header,
                    "method": "GET",
                    "payload": None,
                    "evidence": f"{description}: '{headers[header.lower()]}'",
                })

        return results

    def run(self, urls, forms) -> List[Dict]:
        logger.info("[Headers] Scanning security headers...")
        seen = set()
        for url in urls:
            from urllib.parse import urlparse
            base = urlparse(url)._replace(path="/", query="", fragment="").geturl()
            if base not in seen:
                seen.add(base)
                self.findings.extend(self.scan_url(base))
        logger.info(f"[Headers] Done. Findings: {len(self.findings)}")
        return self.findings
