from fastapi import APIRouter, Request
import logging

router = APIRouter()
logger = logging.getLogger("network_monitor.api.security")

@router.get("/events")
async def get_recent_security_events(request: Request, limit: int = 100):
    """Lấy danh sách các sự kiện an ninh gần đây."""
    manager = request.app.state.monitor
    events = await manager.sec_repo.get_recent(limit)
    return {"status": "success", "data": events}
