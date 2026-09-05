"""
Endpoint /api/events

Trả về nhật ký sự kiện (thiết bị mới, online/offline, đổi IP,
Internet mất/khôi phục kết nối...), hỗ trợ phân trang và lọc theo loại.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Query, Request

logger = logging.getLogger("network_monitor.api.events")
router = APIRouter()


@router.get("/api/events")
async def list_events(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    event_type: Optional[str] = Query(default=None),
):
    event_repo = request.app.state.monitor.event_repo
    return await event_repo.list(limit=limit, offset=offset, event_type=event_type)
