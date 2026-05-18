"""
app/services/fuzzer/engine.py
──────────────────────────────
Core async fuzzing engine.
Injects payloads into discovered parameters, sends requests,
analyses responses, and emits real-time scan log events
via the WebSocket manager.
"""

import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

from backend.app.core.config import settings
from backend.app.core.logging import get_logger
from backend.app.models.scan import ScanStatus
from backend.app.services.fuzzer.detector import detector, DetectionResult
from backend.app.services.crawler.crawler import CrawlResult

logger = get_logger(__name__)

# Callback type for emitting real-time log events to WebSocket
LogCallback = Callable[[dict], Coroutine[Any, Any, None]]


class FuzzTarget:
    """Represents a single injection point to be fuzzed."""

    __slots__ = ("url", "method", "parameter", "form_data", "headers")

    def __init__(
        self,
        url: str,
        method: str = "GET",
        parameter: str = "",
        form_data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.url = url
        self.method = method
        self.parameter = parameter
        self.form_data = form_data or {}
        self.headers = headers or {}


class FuzzResult:
    """Result of fuzzing a single injection point with one payload."""

    def __init__(
        self,
        target: FuzzTarget,
        payload: str,
        category: str,
        status_code: int,
        response_body: str,
        response_time_ms: float,
        detection: DetectionResult,
    ):
        self.target = target
        self.payload = payload
        self.category = category
        self.status_code = status_code
        self.response_body = response_body
        self.response_time_ms = response_time_ms
        self.detection = detection


class FuzzingEngine:
    """
    Async fuzzing engine that:
    1. Builds a list of injection points from crawled endpoints
    2. Iterates payload categories and injects into each parameter
    3. Analyses each response for vulnerability signatures
    4. Emits real-time log events via an async callback
    5. Returns all detected vulnerabilities
    """

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        payloads: Dict[str, List[str]],
        depth: int = 3,
        rate_limit_rps: float = 5.0,
        custom_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        on_log: Optional[LogCallback] = None,
        on_vulnerability: Optional[LogCallback] = None,
        on_progress: Optional[LogCallback] = None,
    ):
        self.scan_id = scan_id
        self.target_url = target_url
        self.payloads = payloads  # {category: [payload, ...]}
        self.depth = depth
        self.delay = 1.0 / rate_limit_rps
        self.custom_headers = custom_headers or {}
        self.cookies = cookies or {}
        self.on_log = on_log
        self.on_vulnerability = on_vulnerability
        self.on_progress = on_progress

        # Runtime counters
        self.total_requests = 0
        self.baseline_ms = 100.0  # Updated after first few requests

    async def fuzz(self, crawl_results: List[CrawlResult]) -> List[FuzzResult]:
        """
        Run the full fuzzing pass over all discovered endpoints.

        Args:
            crawl_results: Output from WebCrawler.crawl()

        Returns:
            List of FuzzResult objects where detection.is_vulnerable is True.
        """
        # Build injection targets from crawl results
        targets = self._build_targets(crawl_results)
        if not targets:
            logger.warning("fuzzer.no_targets", scan_id=self.scan_id)
            targets = [FuzzTarget(url=self.target_url, method="GET", parameter="id")]

        logger.info(
            "fuzzer.start",
            scan_id=self.scan_id,
            targets=len(targets),
            payload_categories=list(self.payloads.keys()),
        )

        vulnerabilities: List[FuzzResult] = []
        total_work = sum(len(p) for p in self.payloads.values()) * len(targets)
        completed = 0

        async with httpx.AsyncClient(
            headers=self._build_headers(),
            cookies=self.cookies,
            timeout=httpx.Timeout(settings.REQUEST_TIMEOUT_SECONDS),
            follow_redirects=True,
            verify=False,
        ) as client:
            # Establish baseline response time
            self.baseline_ms = await self._measure_baseline(client)

            # Use a semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_REQUESTS)

            for target in targets:
                for category, payload_list in self.payloads.items():
                    for payload in payload_list:
                        async with semaphore:
                            result = await self._fuzz_one(
                                client, target, payload, category
                            )
                            completed += 1
                            progress = min(
                                int((completed / max(total_work, 1)) * 100), 99
                            )

                            # Emit scan log to WebSocket
                            if self.on_log:
                                await self.on_log(
                                    {
                                        "id": str(uuid.uuid4()),
                                        "timestamp": datetime.now(
                                            timezone.utc
                                        ).strftime("%H:%M:%S"),
                                        "url": result.target.url,
                                        "payload": payload[:60],
                                        "status": result.status_code,
                                        "method": result.target.method,
                                        "response_time_ms": result.response_time_ms,
                                    }
                                )

                            # Emit progress update
                            if self.on_progress:
                                await self.on_progress(
                                    {
                                        "progress": progress,
                                        "total_requests": self.total_requests,
                                    }
                                )

                            if result.detection.is_vulnerable:
                                vulnerabilities.append(result)
                                if self.on_vulnerability:
                                    await self.on_vulnerability(
                                        self._result_to_vuln_dict(result)
                                    )
                                logger.info(
                                    "fuzzer.vulnerability_found",
                                    type=result.detection.vuln_type,
                                    url=target.url,
                                    severity=result.detection.severity,
                                )

                            # Rate limiting delay
                            await asyncio.sleep(self.delay)

        logger.info(
            "fuzzer.complete",
            scan_id=self.scan_id,
            vulnerabilities=len(vulnerabilities),
            total_requests=self.total_requests,
        )
        return vulnerabilities

    async def _fuzz_one(
        self,
        client: httpx.AsyncClient,
        target: FuzzTarget,
        payload: str,
        category: str,
    ) -> FuzzResult:
        """Inject one payload into one target and analyse the response."""
        self.total_requests += 1
        status_code = 0
        response_body = ""
        response_time_ms = 0.0

        try:
            start = time.monotonic()

            if target.method == "GET":
                fuzz_url = self._inject_into_url(target.url, target.parameter, payload)
                response = await client.get(fuzz_url)
            else:
                # POST with form data or JSON
                form_data = dict(target.form_data)
                if target.parameter:
                    form_data[target.parameter] = payload
                response = await client.post(target.url, data=form_data)

            response_time_ms = (time.monotonic() - start) * 1000
            status_code = response.status_code
            response_body = response.text[:10000]  # cap at 10KB

        except httpx.TimeoutException:
            # Timeout can itself indicate time-based injection success
            response_time_ms = settings.REQUEST_TIMEOUT_SECONDS * 1000
            status_code = 0
            response_body = ""
        except Exception as exc:
            logger.debug("fuzzer.request_error", error=str(exc))
            status_code = 0

        detection = detector.analyse(
            url=target.url,
            payload=payload,
            category=category,
            status_code=status_code,
            response_body=response_body,
            response_time_ms=response_time_ms,
            baseline_time_ms=self.baseline_ms,
        )

        return FuzzResult(
            target=target,
            payload=payload,
            category=category,
            status_code=status_code,
            response_body=response_body,
            response_time_ms=response_time_ms,
            detection=detection,
        )

    async def _measure_baseline(self, client: httpx.AsyncClient) -> float:
        """
        Make 3 clean requests to measure average baseline response time.
        Used for time-based blind injection detection.
        """
        times = []
        for _ in range(3):
            try:
                start = time.monotonic()
                await client.get(self.target_url)
                times.append((time.monotonic() - start) * 1000)
                await asyncio.sleep(0.2)
            except Exception:
                times.append(200.0)

        baseline = sum(times) / len(times) if times else 200.0
        logger.debug("fuzzer.baseline_measured", ms=baseline)
        return baseline

    def _build_targets(self, crawl_results: List[CrawlResult]) -> List[FuzzTarget]:
        """
        Convert crawler results into a flat list of injection points.
        Each (url, parameter) pair becomes one FuzzTarget.
        """
        targets: List[FuzzTarget] = []
        seen = set()

        for result in crawl_results:
            # Query parameter injection points
            for param in result.parameters:
                key = f"{result.url}:{param}:GET"
                if key not in seen:
                    seen.add(key)
                    targets.append(
                        FuzzTarget(
                            url=result.url,
                            method="GET",
                            parameter=param,
                        )
                    )

            # Form field injection points
            for form in result.forms:
                for field_name in form.get("fields", []):
                    key = f"{form['action']}:{field_name}:{form['method']}"
                    if key not in seen:
                        seen.add(key)
                        # Pre-fill other fields with benign values
                        form_data = {f: "test" for f in form.get("fields", [])}
                        targets.append(
                            FuzzTarget(
                                url=form["action"],
                                method=form["method"],
                                parameter=field_name,
                                form_data=form_data,
                            )
                        )

        return targets

    def _inject_into_url(self, url: str, parameter: str, payload: str) -> str:
        """Inject payload into a specific query parameter of a URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if parameter and parameter in params:
            params[parameter] = [payload]
        elif parameter:
            params[parameter] = [payload]
        else:
            # No specific parameter: append as generic 'q'
            params["q"] = [payload]

        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _result_to_vuln_dict(self, result: FuzzResult) -> dict:
        """Convert a FuzzResult to a vulnerability dict for WebSocket emission."""
        return {
            "id": str(uuid.uuid4()),
            "url": result.target.url,
            "parameter": result.target.parameter or "unknown",
            "payload": result.payload,
            "type": result.detection.vuln_type,
            "severity": result.detection.severity,
            "responseSnippet": (
                f"HTTP/1.1 {result.status_code}\n\n" f"{result.response_body[:500]}"
            ),
            "fixRecommendation": "",  # Filled in by payload_engine after
        }

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": "SmartFuzz/1.0 (Authorized Security Testing)",
            "Accept": "*/*",
        }
        headers.update(self.custom_headers)
        return headers
