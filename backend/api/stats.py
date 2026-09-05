"""
Endpoint /api/stats

Trả về số liệu tổng hợp: tổng số thiết bị, số online/offline, độ trễ
trung bình, trạng thái Internet, thời gian hoạt động (uptime), traffic hiện tại...
"""

import logging

from fastapi import APIRouter, Request

logger = logging.getLogger("network_monitor.api.stats")
router = APIRouter()


@router.get("/api/stats")
async def get_stats(request: Request):
    monitor = getattr(request.app.state, "monitor", None) or getattr(request.app.state, "monitor_manager", None)
    return await monitor.get_stats()
