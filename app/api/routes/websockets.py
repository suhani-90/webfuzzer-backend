"""
app/api/routes/websockets.py
──────────────────────────────
WebSocket endpoint for real-time scan progress streaming.

Connect:  ws://host/ws/scans/{scan_id}?token=<jwt_access_token>

The client receives a stream of JSON messages:
  { "type": "scan_log",         "data": { ScanLog fields } }
  { "type": "vulnerability_found", "data": { Vulnerability fields } }
  { "type": "progress_update",  "data": { "progress": 42, "total_requests": 1200 } }
  { "type": "status_update",    "data": { "status": "crawling" } }
  { "type": "scan_complete",    "data": { "progress": 100, ... } }
  { "type": "scan_failed",      "data": { "error": "..." } }
"""

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from jose import JWTError
from sqlalchemy.future import select

from app.core.logging import get_logger
from app.core.security import decode_token, verify_token_type
from app.db.session import AsyncSessionLocal
from app.models.scan import Scan
from app.websockets.manager import ws_manager

logger = get_logger(__name__)
router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/scans/{scan_id}")
async def scan_websocket(
    websocket: WebSocket,
    scan_id: str,
    token: str = Query(..., description="JWT access token for authentication"),
) -> None:
    """
    WebSocket endpoint for real-time scan event streaming.

    Authentication: Pass JWT access token as query parameter ?token=<jwt>
    (Authorization header is not supported over WebSocket by browsers).

    The connection stays open until:
    - The scan completes or fails
    - The client disconnects
    - The server encounters an unrecoverable error
    """
    # ── Authenticate the WebSocket connection ──────────────────────────────────
    user_id = None
    try:
        payload = decode_token(token)
        if not verify_token_type(payload, "access"):
            await websocket.close(code=4001, reason="Invalid token type.")
            return
        user_id = payload.get("sub")
    except JWTError:
        await websocket.close(code=4001, reason="Invalid or expired token.")
        return

    # ── Verify scan ownership ──────────────────────────────────────────────────
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            await websocket.close(code=4004, reason="Scan not found.")
            return

    # ── Accept and register connection ────────────────────────────────────────
    await ws_manager.connect(websocket, scan_id)
    logger.info("ws.connected", scan_id=scan_id, user_id=user_id)

    # Send current scan state immediately on connect
    await websocket.send_json(
        {
            "type": "connected",
            "data": {
                "scan_id": scan_id,
                "status": scan.status,
                "progress": scan.progress,
                "message": "Connected to SmartFuzz live stream.",
            },
        }
    )

    try:
        # Keep connection open; the manager handles broadcasts from Redis
        while True:
            # Listen for any client messages (e.g., "ping" keepalive)
            try:
                message = await websocket.receive_text()
                if message == "ping":
                    await websocket.send_text("pong")
            except Exception:
                break
    except WebSocketDisconnect:
        logger.info("ws.client_disconnect", scan_id=scan_id)
    finally:
        ws_manager.disconnect(websocket, scan_id)
