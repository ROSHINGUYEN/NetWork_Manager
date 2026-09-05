"""
Quản lý các kết nối WebSocket đang hoạt động và phát (broadcast) dữ liệu
realtime tới toàn bộ client đang mở dashboard.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("network_monitor.websocket")


class ConnectionManager:
    """Theo dõi danh sách WebSocket đang kết nối và gửi broadcast an toàn."""

    def __init__(self):
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)
        logger.info(f"Client WebSocket mới kết nối. Tổng số client: {len(self._connections)}")

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)
        logger.info(f"Client WebSocket ngắt kết nối. Tổng số client: {len(self._connections)}")

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Gửi 1 message JSON tới toàn bộ client đang kết nối."""
        if not self._connections:
            return

        payload = json.dumps(message, default=str, ensure_ascii=False)

        async with self._lock:
            targets = list(self._connections)

        stale: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_text(payload)
            except Exception:
                stale.append(ws)

        if stale:
            async with self._lock:
                for ws in stale:
                    if ws in self._connections:
                        self._connections.remove(ws)
