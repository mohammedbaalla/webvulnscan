"""
Crawler - Discovers URLs, forms, and input fields for scanning.
"""

from urllib.parse import urlparse, urljoin, urlencode
from typing import Set, List, Dict, Tuple
from bs4 import BeautifulSoup
import logging
import re

logger = logging.getLogger(__name__)


class Crawler:
    """Crawls a target website to discover pages, forms, and parameters."""

    def __init__(self, session, max_depth: int = 3, scope: str = None):
        self.session = session
        self.max_depth = max_depth
        self.scope = scope
        self.visited: Set[str] = set()
        self.forms: List[Dict] = []
        self.urls: Set[str] = set()

    def _in_scope(self, url: str) -> bool:
        """Check if a URL is within the target scope."""
        if not self.scope:
            return True
        parsed = urlparse(url)
        scope_parsed = urlparse(self.scope)
        return parsed.netloc == scope_parsed.netloc

    def _normalize_url(self, url: str, base: str) -> str:
        """Resolve relative URLs and strip fragments."""
        full = urljoin(base, url)
        parsed = urlparse(full)
        return parsed._replace(fragment="").geturl()

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        """Extract all anchor hrefs from the page."""
        links = set()
        for tag in soup.find_all("a", href=True):
            url = self._normalize_url(tag["href"], base_url)
            if self._in_scope(url):
                links.add(url)
        return links

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract forms with their action, method, and inputs."""
        forms = []
        for form in soup.find_all("form"):
            action = self._normalize_url(form.get("action", base_url), base_url)
            method = form.get("method", "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inp_type = inp.get("type", "text")
                name = inp.get("name")
                value = inp.get("value", "")
                if name and inp_type not in ("submit", "button", "image", "reset", "file"):
                    inputs.append({"name": name, "type": inp_type, "value": value})
            if inputs:
                forms.append({
                    "url": base_url,
                    "action": action,
                    "method": method,
                    "inputs": inputs,
                })
        return forms

    def crawl(self, start_url: str) -> Tuple[Set[str], List[Dict]]:
        """BFS crawl starting from start_url. Returns (urls, forms)."""
        self.scope = self.scope or start_url
        queue = [(start_url, 0)]

        while queue:
            url, depth = queue.pop(0)
            if url in self.visited or depth > self.max_depth:
                continue

            logger.info(f"[Crawler] Visiting ({depth}/{self.max_depth}): {url}")
            self.visited.add(url)
            self.urls.add(url)

            resp = self.session.get(url)
            if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            links = self._extract_links(soup, url)
            forms = self._extract_forms(soup, url)
            self.forms.extend(forms)

            for link in links:
                if link not in self.visited:
                    queue.append((link, depth + 1))

        logger.info(f"[Crawler] Done. Pages: {len(self.urls)}, Forms: {len(self.forms)}")
        return self.urls, self.forms
