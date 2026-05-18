"""
app/services/fuzzer/tasks.py
─────────────────────────────
Celery background tasks that orchestrate the full scan pipeline:
  1. AI payload generation (Gemini)
  2. Web crawling (BFS)
  3. Fuzzing engine
  4. Vulnerability persistence
  5. Report generation
  6. WebSocket progress updates via Redis pub/sub
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

import redis as redis_sync

from backend.app.core.celery_app import celery_app
from backend.app.core.config import settings
from backend.app.core.logging import get_logger

logger = get_logger(__name__)


def _get_redis() -> redis_sync.Redis:
    """Return a synchronous Redis client for Celery task pub/sub."""
    return redis_sync.from_url(settings.REDIS_URL, decode_responses=True)


def _publish_ws_event(scan_id: str, event_type: str, data: dict) -> None:
    """Publish a WebSocket event to Redis for the WS manager to broadcast."""
    r = _get_redis()
    message = json.dumps({"type": event_type, "data": data})
    r.publish(f"scan:{scan_id}", message)


def _update_scan_in_redis(scan_id: str, updates: dict) -> None:
    """Cache scan state in Redis for fast dashboard reads."""
    r = _get_redis()
    key = f"scan_state:{scan_id}"
    existing = r.hgetall(key)
    existing.update({k: str(v) for k, v in updates.items()})
    r.hset(key, mapping=existing)
    r.expire(key, 86400)  # 24h TTL


@celery_app.task(bind=True, name="app.services.fuzzer.tasks.run_scan", max_retries=1)
def run_scan(self, scan_id: str, scan_config: dict) -> dict:
    """
    Main Celery task: orchestrates the entire scan pipeline synchronously
    by running the async pipeline inside asyncio.run().

    Args:
        scan_id: UUID of the Scan record in the database.
        scan_config: Dict matching ScanStartRequest schema.

    Returns:
        Summary dict with scan results.
    """
    logger.info("celery.task.run_scan.start", scan_id=scan_id)
    try:
        result = asyncio.run(_async_scan_pipeline(scan_id, scan_config))
        return result
    except Exception as exc:
        logger.error("celery.task.run_scan.error", scan_id=scan_id, error=str(exc))
        _publish_ws_event(
            scan_id,
            "scan_failed",
            {
                "scan_id": scan_id,
                "error": str(exc),
            },
        )
        # Update DB status to failed
        asyncio.run(_mark_scan_failed(scan_id, str(exc)))
        raise self.retry(exc=exc, countdown=5) if self.request.retries < 1 else exc


async def _async_scan_pipeline(scan_id: str, config: dict) -> dict:
    """
    Full async scan pipeline.
    Imported here to avoid circular imports at module load time.
    """
    # Import inside function to prevent circular imports
    from backend.app.db.session import AsyncSessionLocal
    from backend.app.models.scan import Scan, ScanStatus
    from backend.app.models.endpoint import DiscoveredEndpoint
    from backend.app.models.payload import Payload
    from backend.app.models.vulnerability import Vulnerability
    from backend.app.models.report import Report
    from backend.app.services.ai.payload_engine import payload_engine
    from backend.app.services.crawler.crawler import WebCrawler
    from backend.app.services.fuzzer.engine import FuzzingEngine
    from backend.app.services.reporting.report_builder import ReportBuilder
    from sqlalchemy.future import select

    target_url: str = config["targetUrl"]
    scan_type: str = config.get("scanType", "Full Security Scan")
    depth: int = config.get("depth", 3)
    payload_config: dict = config.get("payloads", {})

    # ── Phase 1: Mark scan as AI generating ───────────────────────────────────
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            logger.error("scan.not_found", scan_id=scan_id)
            return {"error": "Scan not found"}

        scan.status = ScanStatus.AI_GENERATING
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()

    _publish_ws_event(
        scan_id,
        "status_update",
        {
            "status": "ai_generating",
            "message": "Gemini AI is synthesizing attack payloads...",
        },
    )

    # ── Phase 2: Generate payloads ────────────────────────────────────────────
    payloads_dict = await payload_engine.generate(
        target_url=target_url,
        scan_type=scan_type,
        include_sql=payload_config.get("sql", True),
        include_xss=payload_config.get("xss", True),
        include_rce=False,
        include_auth=False,
        include_overflow=payload_config.get("longString", False),
        include_special=payload_config.get("specialChar", False),
        custom_context=payload_config.get("custom", ""),
    )

    # Persist generated payloads to DB
    async with AsyncSessionLocal() as db:
        for category, payload_list in payloads_dict.items():
            for p_value in payload_list:
                db.add(
                    Payload(
                        scan_id=scan_id,
                        value=p_value,
                        category=category,
                        is_ai_generated=False,  # Will refine later
                    )
                )
        await db.commit()

    all_payloads_flat = [p for pl in payloads_dict.values() for p in pl]
    _publish_ws_event(
        scan_id,
        "payloads_ready",
        {
            "count": len(all_payloads_flat),
            "categories": list(payloads_dict.keys()),
        },
    )

    # ── Phase 3: Crawl target ─────────────────────────────────────────────────
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        scan.status = ScanStatus.CRAWLING
        await db.commit()

    _publish_ws_event(scan_id, "status_update", {"status": "crawling"})

    crawler = WebCrawler(
        base_url=target_url,
        max_depth=min(depth, settings.MAX_CRAWL_DEPTH),
        rate_limit_rps=5.0,
    )
    crawl_results = await crawler.crawl()

    # Persist discovered endpoints
    async with AsyncSessionLocal() as db:
        for cr in crawl_results:
            db.add(
                DiscoveredEndpoint(
                    scan_id=scan_id,
                    url=cr.url,
                    method=cr.method,
                    parameters=cr.parameters,
                    forms=cr.forms,
                    headers=cr.headers,
                    status_code=cr.status_code,
                    content_type=cr.content_type,
                )
            )
        scan_record = (
            await db.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one()
        scan_record.total_endpoints = len(crawl_results)
        scan_record.status = ScanStatus.FUZZING
        await db.commit()

    _publish_ws_event(
        scan_id,
        "crawl_complete",
        {
            "endpoints_found": len(crawl_results),
            "status": "fuzzing",
        },
    )

    # ── Phase 4: Fuzz ─────────────────────────────────────────────────────────
    total_requests_counter = [0]
    vuln_records = []

    async def on_log(log_entry: dict):
        total_requests_counter[0] += 1
        log_entry["scan_id"] = scan_id
        _publish_ws_event(scan_id, "scan_log", log_entry)
        _update_scan_in_redis(
            scan_id,
            {
                "total_requests": total_requests_counter[0],
                "progress": log_entry.get("progress", 0),
            },
        )

    async def on_vulnerability(vuln_data: dict):
        # Get AI remediation
        fix = await payload_engine.generate_remediation(
            vuln_type=vuln_data.get("type", "Unknown"),
            url=vuln_data.get("url", ""),
            parameter=vuln_data.get("parameter", ""),
            payload=vuln_data.get("payload", ""),
        )
        vuln_data["fixRecommendation"] = fix
        vuln_data["fix_recommendation"] = fix

        # Persist to DB
        async with AsyncSessionLocal() as db:
            vuln = Vulnerability(
                id=vuln_data.get("id", str(uuid.uuid4())),
                scan_id=scan_id,
                url=vuln_data["url"],
                parameter=vuln_data["parameter"],
                payload=vuln_data["payload"],
                type=vuln_data["type"],
                severity=vuln_data["severity"],
                response_snippet=vuln_data.get("responseSnippet", ""),
                fix_recommendation=fix,
                ai_remediation=fix,
            )
            db.add(vuln)

            # Increment counter on scan record
            scan_rec = (
                await db.execute(select(Scan).where(Scan.id == scan_id))
            ).scalar_one()
            scan_rec.vulnerabilities_found += 1
            await db.commit()

        vuln_records.append(vuln_data)
        _publish_ws_event(scan_id, "vulnerability_found", vuln_data)

    async def on_progress(progress_data: dict):
        _publish_ws_event(scan_id, "progress_update", progress_data)

    engine = FuzzingEngine(
        scan_id=scan_id,
        target_url=target_url,
        payloads=payloads_dict,
        depth=depth,
        on_log=on_log,
        on_vulnerability=on_vulnerability,
        on_progress=on_progress,
    )
    fuzz_results = await engine.fuzz(crawl_results)

    # ── Phase 5: Generate report ──────────────────────────────────────────────
    async with AsyncSessionLocal() as db:
        scan_rec = (
            await db.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one()
        scan_rec.status = ScanStatus.COMPLETED
        scan_rec.progress = 100
        scan_rec.completed_at = datetime.now(timezone.utc)
        scan_rec.total_requests = total_requests_counter[0]
        await db.commit()

    builder = ReportBuilder()
    await builder.build_and_save(scan_id)

    _publish_ws_event(
        scan_id,
        "scan_complete",
        {
            "scan_id": scan_id,
            "progress": 100,
            "status": "completed",
            "vulnerabilities_found": len(vuln_records),
            "total_requests": total_requests_counter[0],
        },
    )

    logger.info("pipeline.complete", scan_id=scan_id, vulns=len(vuln_records))
    return {"scan_id": scan_id, "vulnerabilities": len(vuln_records)}


async def _mark_scan_failed(scan_id: str, error: str) -> None:
    """Update scan status to FAILED in the database."""
    from backend.app.db.session import AsyncSessionLocal
    from backend.app.models.scan import Scan, ScanStatus
    from sqlalchemy.future import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = error[:2000]
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
