"""
HTTP Session Manager - Handles all HTTP requests with retry, proxy, and auth support.
"""

import requests
import urllib3
from urllib.parse import urlparse, urljoin
from typing import Optional, Dict, List
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages HTTP sessions with configurable settings."""

    DEFAULT_HEADERS = {
        "User-Agent": "WebVulnScan/1.0 (Security Research)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: int = 10,
        verify_ssl: bool = False,
        cookies: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        max_retries: int = 3,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update(self.DEFAULT_HEADERS)

        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        adapter = requests.adapters.HTTPAdapter(max_retries=max_retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Perform a GET request."""
        try:
            resp = self.session.get(
                url, timeout=self.timeout, verify=self.verify_ssl, **kwargs
            )
            logger.debug(f"GET {url} -> {resp.status_code}")
            return resp
        except requests.RequestException as e:
            logger.warning(f"GET {url} failed: {e}")
            return None

    def post(self, url: str, data: Dict = None, **kwargs) -> Optional[requests.Response]:
        """Perform a POST request."""
        try:
            resp = self.session.post(
                url, data=data, timeout=self.timeout, verify=self.verify_ssl, **kwargs
            )
            logger.debug(f"POST {url} -> {resp.status_code}")
            return resp
        except requests.RequestException as e:
            logger.warning(f"POST {url} failed: {e}")
            return None

    def close(self):
        self.session.close()
