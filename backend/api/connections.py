from fastapi import APIRouter, Request
import logging

router = APIRouter()
logger = logging.getLogger("network_monitor.api.connections")

@router.get("/")
async def get_recent_connections(request: Request, limit: int = 100):
    """Lấy danh sách các kết nối gần đây."""
    manager = request.app.state.monitor
    conns = await manager.conn_repo.get_recent(limit)
    return {"status": "success", "data": conns}
