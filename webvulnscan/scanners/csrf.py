"""
CSRF Scanner - Detects missing or bypassable CSRF protections on state-changing forms.
"""

from typing import List, Dict, Optional
from bs4 import BeautifulSoup
import re
import logging

logger = logging.getLogger(__name__)


# Common CSRF token field names
CSRF_FIELD_NAMES = {
    "csrf_token", "csrftoken", "csrf", "_csrf", "csrf_field",
    "xsrf_token", "xsrftoken", "_xsrf",
    "authenticity_token", "token", "request_token",
    "__requestverificationtoken",
}

# Common CSRF token header names
CSRF_HEADER_NAMES = {
    "x-csrf-token", "x-xsrf-token", "x-csrftoken",
    "x-requested-with",
}

# Patterns suggesting a value looks like a real token
TOKEN_ENTROPY_MIN_LENGTH = 16


class CSRFScanner:
    """
    Checks for CSRF vulnerabilities on POST forms by examining:
    1. Missing CSRF tokens entirely
    2. Weak/predictable token values
    3. Tokens not validated server-side (by replaying with modified token)
    """

    def __init__(self, session):
        self.session = session
        self.findings: List[Dict] = []

    def _get_response_headers(self, url: str) -> Dict:
        """Fetch headers from a URL (HEAD request fallback to GET)."""
        resp = self.session.session.head(url, allow_redirects=True)
        if resp:
            return dict(resp.headers)
        return {}

    def _has_csrf_token_in_form(self, form: Dict) -> Optional[str]:
        """Return the token field name if a CSRF token input exists."""
        for inp in form["inputs"]:
            if inp["name"].lower() in CSRF_FIELD_NAMES:
                return inp["name"]
        return None

    def _token_looks_strong(self, value: str) -> bool:
        """Heuristic: token is long and appears random."""
        if not value or len(value) < TOKEN_ENTROPY_MIN_LENGTH:
            return False
        # Should contain mixed chars, not just digits
        has_alpha = bool(re.search(r"[a-zA-Z]", value))
        has_digit = bool(re.search(r"\d", value))
        return has_alpha and has_digit

    def _test_token_validation(self, form: Dict, token_field: str) -> bool:
        """
        Test if server validates the CSRF token by submitting a bogus one.
        Returns True if the server accepted the bogus token (CSRF bypass possible).
        """
        action = form["action"]
        method = form["method"]
        data = {i["name"]: i["value"] or "test" for i in form["inputs"]}
        original_token = data.get(token_field, "")

        # First get a valid baseline response
        if method == "post":
            baseline = self.session.post(action, data=data)
        else:
            baseline = self.session.get(action, params=data)

        if not baseline:
            return False
        baseline_status = baseline.status_code

        # Now submit with a bogus token
        data[token_field] = "AAAAAAAAAAAAAAAA_BOGUS_TOKEN_AAAAAAAAAAAAAAAA"
        if method == "post":
            bogus_resp = self.session.post(action, data=data)
        else:
            bogus_resp = self.session.get(action, params=data)

        if not bogus_resp:
            return False

        # If the server returned the same status and didn't redirect to an error page,
        # it likely accepted the bogus token
        if bogus_resp.status_code == baseline_status and bogus_resp.status_code in (200, 302):
            # Additional check: look for error keywords in response
            error_keywords = ["invalid token", "csrf", "forbidden", "invalid request", "expired"]
            body_lower = bogus_resp.text.lower()
            if not any(kw in body_lower for kw in error_keywords):
                return True  # Server accepted bogus token

        return False

    def scan_form(self, form: Dict) -> List[Dict]:
        """Analyze a single form for CSRF weaknesses."""
        results = []
        action = form["action"]
        method = form["method"]

        # Only state-changing methods are vulnerable
        if method.lower() not in ("post", "put", "delete", "patch"):
            return []

        token_field = self._has_csrf_token_in_form(form)

        if not token_field:
            results.append({
                "type": "CSRF",
                "subtype": "Missing Token",
                "severity": "High",
                "url": action,
                "parameter": None,
                "method": method.upper(),
                "payload": None,
                "evidence": f"POST form at '{action}' has no CSRF token field. "
                            f"Fields found: {[i['name'] for i in form['inputs']]}",
            })
            logger.warning(f"[CSRF] No token in form at {action}")
            return results

        # Token exists — check quality
        token_value = next(
            (i["value"] for i in form["inputs"] if i["name"] == token_field), ""
        )

        if not self._token_looks_strong(token_value):
            results.append({
                "type": "CSRF",
                "subtype": "Weak Token",
                "severity": "Medium",
                "url": action,
                "parameter": token_field,
                "method": method.upper(),
                "payload": token_value,
                "evidence": f"CSRF token '{token_field}' has a weak/short/predictable value: '{token_value}'",
            })
            logger.warning(f"[CSRF] Weak token in form at {action}")

        # Test server-side validation
        if self._test_token_validation(form, token_field):
            results.append({
                "type": "CSRF",
                "subtype": "Token Not Validated",
                "severity": "Critical",
                "url": action,
                "parameter": token_field,
                "method": method.upper(),
                "payload": "AAAAAAAAAAAAAAAA_BOGUS_TOKEN_AAAAAAAAAAAAAAAA",
                "evidence": f"Server accepted a forged CSRF token for field '{token_field}'. "
                            f"Token validation may be missing server-side.",
            })
            logger.warning(f"[CSRF] Token not validated server-side at {action}")

        return results

    def run(self, urls, forms) -> List[Dict]:
        logger.info("[CSRF] Starting scan...")
        for form in forms:
            self.findings.extend(self.scan_form(form))
        logger.info(f"[CSRF] Done. Findings: {len(self.findings)}")
        return self.findings
