"""
app/services/crawler/tasks.py
──────────────────────────────
Celery background tasks for the web crawler module.
These tasks can be dispatched independently when only crawling
is needed (e.g., endpoint discovery without fuzzing).

Registered in celery_app.py under the "crawling" queue.
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional

from app.core.celery_app import celery_app
from app.core.logging import get_logger

logger = get_logger(__name__)


@celery_app.task(
    bind=True,
    name="app.services.crawler.tasks.crawl_target",
    queue="crawling",
    max_retries=2,
)
def crawl_target(
    self,
    scan_id: str,
    target_url: str,
    max_depth: int = 3,
    rate_limit_rps: float = 5.0,
    custom_headers: Optional[dict] = None,
    cookies: Optional[dict] = None,
) -> dict:
    """
    Celery task: crawl a target URL and persist all discovered endpoints.

    This task can be used standalone (endpoint discovery only) or is
    called internally by the main run_scan pipeline task.

    Args:
        scan_id:        UUID of the Scan record to attach endpoints to.
        target_url:     Base URL to start crawling from.
        max_depth:      BFS crawl depth limit (1–10).
        rate_limit_rps: Requests per second (respects target server).
        custom_headers: Optional HTTP headers to include in each request.
        cookies:        Optional cookies for authenticated crawling.

    Returns:
        Dict with crawl summary: { endpoints_found, urls_visited, scan_id }
    """
    logger.info(
        "celery.crawl_target.start",
        scan_id=scan_id,
        target=target_url,
        depth=max_depth,
    )
    try:
        result = asyncio.run(
            _async_crawl(
                scan_id=scan_id,
                target_url=target_url,
                max_depth=max_depth,
                rate_limit_rps=rate_limit_rps,
                custom_headers=custom_headers or {},
                cookies=cookies or {},
            )
        )
        logger.info("celery.crawl_target.complete", scan_id=scan_id, **result)
        return result
    except Exception as exc:
        logger.error("celery.crawl_target.error", scan_id=scan_id, error=str(exc))
        raise self.retry(exc=exc, countdown=10)


async def _async_crawl(
    scan_id: str,
    target_url: str,
    max_depth: int,
    rate_limit_rps: float,
    custom_headers: dict,
    cookies: dict,
) -> dict:
    """
    Async implementation of the crawl task.
    Runs the WebCrawler and persists DiscoveredEndpoint records to the DB.
    """
    from app.db.session import AsyncSessionLocal
    from app.models.endpoint import DiscoveredEndpoint
    from app.models.scan import Scan, ScanStatus
    from app.services.crawler.crawler import WebCrawler
    from sqlalchemy.future import select

    # ── Update scan status to CRAWLING ────────────────────────────────────────
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            scan.status = ScanStatus.CRAWLING
            await db.commit()

    # ── Run the BFS crawler ───────────────────────────────────────────────────
    crawler = WebCrawler(
        base_url=target_url,
        max_depth=max_depth,
        rate_limit_rps=rate_limit_rps,
        custom_headers=custom_headers,
        cookies=cookies,
    )
    crawl_results = await crawler.crawl()

    # ── Persist discovered endpoints ──────────────────────────────────────────
    endpoints_saved = 0
    async with AsyncSessionLocal() as db:
        for cr in crawl_results:
            endpoint = DiscoveredEndpoint(
                scan_id=scan_id,
                url=cr.url,
                method=cr.method,
                parameters=cr.parameters,
                forms=cr.forms,
                headers=cr.headers,
                status_code=cr.status_code,
                content_type=cr.content_type,
            )
            db.add(endpoint)
            endpoints_saved += 1

        # Update scan's endpoint count
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            scan.total_endpoints = endpoints_saved

        await db.commit()

    logger.info(
        "crawler.task.endpoints_persisted",
        scan_id=scan_id,
        count=endpoints_saved,
    )

    return {
        "scan_id": scan_id,
        "endpoints_found": endpoints_saved,
        "urls_visited": len(crawl_results),
        "target_url": target_url,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }


@celery_app.task(
    name="app.services.crawler.tasks.get_crawl_status",
    queue="crawling",
)
def get_crawl_status(scan_id: str) -> dict:
    """
    Retrieve the current crawl progress for a given scan.
    Returns endpoint count and current scan status from the DB.
    """
    result = asyncio.run(_async_get_status(scan_id))
    return result


async def _async_get_status(scan_id: str) -> dict:
    """Fetch crawl status from the database."""
    from app.db.session import AsyncSessionLocal
    from app.models.scan import Scan
    from sqlalchemy.future import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return {"error": "Scan not found", "scan_id": scan_id}
        return {
            "scan_id": scan_id,
            "status": scan.status,
            "total_endpoints": scan.total_endpoints,
            "progress": scan.progress,
        }
