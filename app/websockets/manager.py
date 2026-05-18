"""
app/websockets/manager.py
──────────────────────────
WebSocket connection manager.
Maintains active connections per scan_id and broadcasts
events published to Redis pub/sub channels by Celery workers.
"""

import asyncio
import json
from collections import defaultdict
from typing import Dict, Set

import redis.asyncio as aioredis
from fastapi import WebSocket
from starlette.websockets import WebSocketState

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections grouped by scan_id.

    Architecture:
    ┌─────────────┐   Redis pub/sub   ┌──────────────┐   WebSocket   ┌──────────┐
    │ Celery task │ ──────────────── ▶│  WS Manager  │ ────────────▶ │ Frontend │
    └─────────────┘                   └──────────────┘               └──────────┘

    The Celery scan worker publishes events to Redis channel "scan:{scan_id}".
    The WebSocket manager subscribes per-client and broadcasts to all
    connected browsers watching that scan.
    """

    def __init__(self):
        # scan_id → set of active WebSocket connections
        self._connections: Dict[str, Set[WebSocket]] = defaultdict(set)
        # scan_id → asyncio task running the Redis subscriber
        self._subscriber_tasks: Dict[str, asyncio.Task] = {}

    async def connect(self, websocket: WebSocket, scan_id: str) -> None:
        """Accept and register a new WebSocket connection for a scan."""
        await websocket.accept()
        self._connections[scan_id].add(websocket)
        logger.info(
            "ws.client_connected",
            scan_id=scan_id,
            total=len(self._connections[scan_id]),
        )

        # Start Redis subscriber for this scan if not already running
        if scan_id not in self._subscriber_tasks:
            task = asyncio.create_task(self._redis_subscriber(scan_id))
            self._subscriber_tasks[scan_id] = task

    def disconnect(self, websocket: WebSocket, scan_id: str) -> None:
        """Remove a disconnected WebSocket from the registry."""
        self._connections[scan_id].discard(websocket)
        logger.info(
            "ws.client_disconnected",
            scan_id=scan_id,
            remaining=len(self._connections[scan_id]),
        )

        # Cancel Redis subscriber if no more clients are watching this scan
        if not self._connections[scan_id]:
            task = self._subscriber_tasks.pop(scan_id, None)
            if task:
                task.cancel()

    async def broadcast(self, scan_id: str, message: dict) -> None:
        """Send a JSON message to all WebSocket clients watching scan_id."""
        if scan_id not in self._connections:
            return

        dead_sockets: Set[WebSocket] = set()
        payload = json.dumps(message)

        for ws in list(self._connections[scan_id]):
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.send_text(payload)
            except Exception as exc:
                logger.warning("ws.send_failed", scan_id=scan_id, error=str(exc))
                dead_sockets.add(ws)

        # Clean up dead connections
        for ws in dead_sockets:
            self._connections[scan_id].discard(ws)

    async def _redis_subscriber(self, scan_id: str) -> None:
        """
        Subscribe to Redis pub/sub channel for scan_id and relay messages
        to all connected WebSocket clients.
        Runs as a long-lived asyncio task per active scan.
        """
        channel = f"scan:{scan_id}"
        logger.info("ws.redis_subscriber.start", channel=channel)

        try:
            redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            pubsub = redis.pubsub()
            await pubsub.subscribe(channel)

            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue

                try:
                    data = json.loads(message["data"])
                    await self.broadcast(scan_id, data)

                    # Stop subscribing when scan completes or fails
                    event_type = data.get("type", "")
                    if event_type in ("scan_complete", "scan_failed"):
                        logger.info("ws.redis_subscriber.scan_done", scan_id=scan_id)
                        break

                except json.JSONDecodeError:
                    logger.warning("ws.bad_redis_message", data=message["data"][:100])

            await pubsub.unsubscribe(channel)
            await redis.aclose()

        except asyncio.CancelledError:
            logger.info("ws.redis_subscriber.cancelled", scan_id=scan_id)
        except Exception as exc:
            logger.error("ws.redis_subscriber.error", scan_id=scan_id, error=str(exc))


# Module-level singleton shared across all WebSocket route handlers
ws_manager = ConnectionManager()
