"""
Endpoint /api/network

Trả về thông tin mạng cục bộ hiện tại: local IP, gateway, subnet,
network interface, trạng thái Internet và lịch sử traffic gần nhất.
"""

import logging

from fastapi import APIRouter, Request

from backend.services.interface_info import get_active_adapter_info
from backend.services.network_info import lookup_isp_info

logger = logging.getLogger("network_monitor.api.network")
router = APIRouter()


@router.get("/api/network")
async def get_network_info(request: Request):
    monitor = request.app.state.monitor
    info = monitor.get_network_info()
    info["traffic_history"] = monitor.get_traffic_history(limit=60)
    info["adapter"] = get_active_adapter_info(info.get("interface"))
    return info


@router.get("/api/network/adapter")
async def get_adapter_info(request: Request):
    monitor = request.app.state.monitor
    info = monitor.get_network_info()
    return get_active_adapter_info(info.get("interface"))


@router.post("/api/network/isp-lookup")
async def get_isp_info():
    """Tra cứu ISP, ASN và Public IP chỉ khi người dùng cho phép (Opt-in)."""
    return await lookup_isp_info()
