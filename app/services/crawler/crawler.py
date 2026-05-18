"""
app/services/crawler/crawler.py
────────────────────────────────
Async BFS (breadth-first search) web crawler.
Discovers links, forms, query parameters, and REST API endpoints.
Respects robots.txt, rate limiting, and configurable depth.
"""

import asyncio
import re
import time
from collections import deque
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import httpx
from bs4 import BeautifulSoup

from app.core.config import settings
from app.core.logging import get_logger
from app.services.crawler.parser import PageParser
from app.utils.url_validator import URLValidator

logger = get_logger(__name__)


class CrawlResult:
    """Container for all data discovered from a single URL."""

    __slots__ = (
        "url",
        "method",
        "parameters",
        "forms",
        "headers",
        "status_code",
        "content_type",
        "links",
    )

    def __init__(
        self,
        url: str,
        method: str = "GET",
        parameters: Optional[List[str]] = None,
        forms: Optional[List[dict]] = None,
        headers: Optional[Dict[str, str]] = None,
        status_code: int = 200,
        content_type: str = "",
        links: Optional[List[str]] = None,
    ):
        self.url = url
        self.method = method
        self.parameters = parameters or []
        self.forms = forms or []
        self.headers = headers or {}
        self.status_code = status_code
        self.content_type = content_type
        self.links = links or []


class WebCrawler:
    """
    Async BFS crawler that discovers all reachable endpoints within a domain.

    Features:
    - Async HTTP requests via httpx
    - BFS queue with configurable max depth
    - Duplicate URL detection (normalised)
    - robots.txt awareness
    - Configurable rate limiting (delay between requests)
    - Form and query parameter extraction
    - Respects max_urls_per_scan limit
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        rate_limit_rps: float = 5.0,
        custom_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: int = 10,
    ):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.delay = 1.0 / rate_limit_rps  # seconds between requests
        self.custom_headers = custom_headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.parser = PageParser()
        self.validator = URLValidator()

        # Runtime state
        self._visited: Set[str] = set()
        self._disallowed: Set[str] = set()
        self._results: List[CrawlResult] = []

    async def crawl(self) -> List[CrawlResult]:
        """
        Run the full BFS crawl starting from base_url.

        Returns:
            List of CrawlResult objects for each discovered endpoint.
        """
        logger.info("crawler.start", url=self.base_url, max_depth=self.max_depth)

        # Fetch and parse robots.txt
        await self._load_robots_txt()

        # BFS queue: (url, depth)
        queue: deque = deque([(self.base_url, 0)])
        self._visited.add(self._normalise(self.base_url))

        async with httpx.AsyncClient(
            headers=self._build_headers(),
            cookies=self.cookies,
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            verify=False,  # Allow self-signed certs in test targets
        ) as client:
            while queue and len(self._results) < settings.MAX_URLS_PER_SCAN:
                url, depth = queue.popleft()

                if depth > self.max_depth:
                    continue

                # Rate limiting
                await asyncio.sleep(self.delay)

                result = await self._fetch_and_parse(client, url)
                if result is None:
                    continue

                self._results.append(result)
                logger.debug(
                    "crawler.page_discovered",
                    url=url,
                    depth=depth,
                    params=len(result.parameters),
                    forms=len(result.forms),
                )

                # Enqueue discovered links for next depth
                if depth < self.max_depth:
                    for link in result.links:
                        norm = self._normalise(link)
                        if (
                            norm not in self._visited
                            and self._is_same_domain(link)
                            and not self._is_disallowed(link)
                        ):
                            self._visited.add(norm)
                            queue.append((link, depth + 1))

        logger.info(
            "crawler.complete",
            pages=len(self._results),
            unique_urls=len(self._visited),
        )
        return self._results

    async def _fetch_and_parse(
        self, client: httpx.AsyncClient, url: str
    ) -> Optional[CrawlResult]:
        """Fetch a URL and extract all useful data from the response."""
        try:
            start = time.monotonic()
            response = await client.get(url)
            elapsed = (time.monotonic() - start) * 1000

            content_type = response.headers.get("content-type", "")
            status_code = response.status_code
            headers = dict(response.headers)

            # Only parse HTML pages
            if "html" not in content_type:
                return CrawlResult(
                    url=url,
                    status_code=status_code,
                    content_type=content_type,
                    headers=headers,
                )

            html = response.text
            soup = BeautifulSoup(html, "lxml")

            links = self.parser.extract_links(soup, url)
            forms = self.parser.extract_forms(soup, url)
            query_params = self.parser.extract_query_params(url)

            # Also extract params from discovered form fields
            all_params = list(query_params)
            for form in forms:
                all_params.extend(form.get("fields", []))

            return CrawlResult(
                url=url,
                method="GET",
                parameters=list(set(all_params)),
                forms=forms,
                headers=headers,
                status_code=status_code,
                content_type=content_type,
                links=links,
            )

        except httpx.TimeoutException:
            logger.warning("crawler.timeout", url=url)
        except httpx.RequestError as exc:
            logger.warning("crawler.request_error", url=url, error=str(exc))
        except Exception as exc:
            logger.error("crawler.unexpected_error", url=url, error=str(exc))
        return None

    async def _load_robots_txt(self) -> None:
        """Fetch robots.txt and populate the disallowed set."""
        robots_url = f"{self.base_url}/robots.txt"
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(robots_url)
                if response.status_code == 200:
                    for line in response.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                self._disallowed.add(path)
            logger.debug("crawler.robots_loaded", disallowed=len(self._disallowed))
        except Exception:
            pass  # robots.txt is optional

    def _is_disallowed(self, url: str) -> bool:
        """Return True if the URL path matches a robots.txt Disallow rule."""
        path = urlparse(url).path
        return any(path.startswith(d) for d in self._disallowed)

    def _is_same_domain(self, url: str) -> bool:
        """Return True if the URL belongs to the same domain as the target."""
        return urlparse(url).netloc == self.base_domain

    def _normalise(self, url: str) -> str:
        """Normalise a URL for deduplication (strip fragment, sort params)."""
        parsed = urlparse(url)
        return parsed._replace(fragment="").geturl().rstrip("/").lower()

    def _build_headers(self) -> Dict[str, str]:
        """Build the HTTP headers dict for all crawler requests."""
        headers = {
            "User-Agent": (
                "SmartFuzz/1.0 (+https://github.com/smartfuzz; "
                "authorized-security-testing)"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        headers.update(self.custom_headers)
        return headers
