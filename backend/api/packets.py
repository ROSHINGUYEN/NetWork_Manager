from fastapi import APIRouter, Request
import logging

router = APIRouter()
logger = logging.getLogger("network_monitor.api.packets")

@router.get("/")
async def get_recent_packets(request: Request, limit: int = 100):
    """Lấy danh sách các gói tin gần đây."""
    manager = request.app.state.monitor
    packets = await manager.packet_repo.get_recent(limit)
    return {"status": "success", "data": packets}

@router.get("/stats")
async def get_packet_stats(request: Request):
    """Lấy thống kê gói tin (tổng số, giao thức)."""
    manager = request.app.state.monitor
    sniffer = getattr(manager, "packet_sniffer", None)
    if sniffer:
        return {"status": "success", "data": sniffer.stats}
    return {"status": "error", "message": "Packet sniffer not running"}
