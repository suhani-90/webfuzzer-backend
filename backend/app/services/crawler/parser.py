"""
app/services/crawler/parser.py
────────────────────────────────
HTML parser utilities for the web crawler.
Extracts links, forms, query parameters, and API endpoint hints.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup, Tag

from backend.app.core.logging import get_logger

logger = get_logger(__name__)

# Regex patterns for API endpoint discovery in JavaScript
API_ENDPOINT_PATTERNS = [
    re.compile(r'["\'](/api/[^"\'?\s]+)', re.IGNORECASE),
    re.compile(r'["\'](/v\d+/[^"\'?\s]+)', re.IGNORECASE),
    re.compile(r'fetch\(["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'axios\.[a-z]+\(["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'\.get\(["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'\.post\(["\']([^"\']+)["\']', re.IGNORECASE),
]


class PageParser:
    """
    Stateless utility class for extracting security-relevant
    data from HTML pages.
    """

    def extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """
        Extract all absolute hyperlinks from <a href> and <form action> tags.

        Args:
            soup: Parsed HTML document.
            base_url: Used to resolve relative URLs.

        Returns:
            Deduplicated list of absolute URL strings.
        """
        links: List[str] = []
        seen: set = set()

        # <a href="...">
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            abs_url = urljoin(base_url, href)
            if abs_url not in seen:
                seen.add(abs_url)
                links.append(abs_url)

        # <form action="...">
        for form in soup.find_all("form", action=True):
            action = form["action"].strip()
            if action:
                abs_url = urljoin(base_url, action)
                if abs_url not in seen:
                    seen.add(abs_url)
                    links.append(abs_url)

        # Scan inline scripts for API endpoints
        for script in soup.find_all("script"):
            if script.string:
                api_links = self._extract_api_endpoints(script.string, base_url)
                for link in api_links:
                    if link not in seen:
                        seen.add(link)
                        links.append(link)

        return links

    def extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[dict]:
        """
        Extract all HTML forms with their fields and metadata.

        Returns:
            List of dicts: {action, method, fields: [field_name, ...], inputs: [...]}
        """
        forms = []
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            method = form_tag.get("method", "GET").upper()
            abs_action = urljoin(base_url, action) if action else base_url

            # Extract all named input fields
            fields = []
            inputs = []
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if name:
                    fields.append(name)
                    inputs.append(
                        {
                            "name": name,
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        }
                    )

            if fields:  # Only record forms with injectable fields
                forms.append(
                    {
                        "action": abs_action,
                        "method": method,
                        "fields": fields,
                        "inputs": inputs,
                        "enctype": form_tag.get(
                            "enctype", "application/x-www-form-urlencoded"
                        ),
                    }
                )

        return forms

    def extract_query_params(self, url: str) -> List[str]:
        """
        Extract parameter names from a URL's query string.

        Example: /search?q=hello&page=1 → ['q', 'page']
        """
        parsed = urlparse(url)
        if not parsed.query:
            return []
        return list(parse_qs(parsed.query).keys())

    def _extract_api_endpoints(self, js_code: str, base_url: str) -> List[str]:
        """
        Scan inline JavaScript for API endpoint strings.
        Helps discover REST APIs not linked in HTML.
        """
        found = []
        for pattern in API_ENDPOINT_PATTERNS:
            for match in pattern.finditer(js_code):
                path = match.group(1)
                try:
                    abs_url = urljoin(base_url, path)
                    found.append(abs_url)
                except Exception:
                    pass
        return found
