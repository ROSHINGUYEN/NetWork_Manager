"""
Endpoint /api/devices

- GET  /api/devices             : danh sách toàn bộ thiết bị (lọc theo status tuỳ chọn)
- GET  /api/devices/{mac}       : chi tiết 1 thiết bị + lịch sử đổi IP
- POST /api/devices/scan        : kích hoạt quét mạng ngay lập tức
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

from pydantic import BaseModel

logger = logging.getLogger("network_monitor.api.devices")
router = APIRouter()


class DeviceUpdatePayload(BaseModel):
    custom_name: Optional[str] = None
    device_type: Optional[str] = None


@router.get("/api/devices")
async def list_devices(
    request: Request,
    status: Optional[str] = Query(default=None, description="Lọc theo 'online' hoặc 'offline'"),
):
    device_repo = request.app.state.monitor.device_repo
    if status in ("online", "offline"):
        return await device_repo.get_by_status(status)
    return await device_repo.get_all()


@router.get("/api/devices/{mac}")
async def get_device_detail(mac: str, request: Request):
    monitor = request.app.state.monitor
    mac_normalized = mac.upper().replace("-", ":")

    device = await monitor.device_repo.get_by_mac(mac_normalized)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Không tìm thấy thiết bị với MAC {mac}")

    history = await monitor.ip_history_repo.get_for_mac(mac_normalized)
    device = dict(device)
    device["ip_history"] = history
    return device


@router.patch("/api/devices/{mac}")
async def update_device_info(mac: str, payload: DeviceUpdatePayload, request: Request):
    """Cập nhật tên gợi nhớ (custom_name) hoặc loại thiết bị (device_type)."""
    monitor = request.app.state.monitor
    mac_normalized = mac.upper().replace("-", ":")

    device = await monitor.device_repo.get_by_mac(mac_normalized)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Không tìm thấy thiết bị với MAC {mac}")

    new_name = payload.custom_name if payload.custom_name is not None else (device.get("custom_name") or "")
    new_type = payload.device_type if payload.device_type is not None else (device.get("device_type") or "")

    await monitor.device_repo.update_custom_info(mac_normalized, new_name, new_type)

    # Đẩy cập nhật tức thời qua WebSocket cho mọi dashboard đang mở
    all_devices = await monitor.device_repo.get_all()
    await monitor.ws_manager.broadcast({"type": "devices_update", "data": all_devices})

    return {
        "status": "success",
        "mac": mac_normalized,
        "custom_name": new_name,
        "device_type": new_type,
    }


class ScanPayload(BaseModel):
    range: Optional[str] = None


@router.post("/api/devices/scan")
async def trigger_manual_scan(request: Request, payload: Optional[ScanPayload] = None):
    monitor = request.app.state.monitor
    target_range = payload.range.strip() if (payload and payload.range and payload.range.strip()) else None
    await monitor.trigger_scan(target_range=target_range)
    logger.info(f"Đã nhận yêu cầu quét mạng thủ công từ API: target={target_range or 'mặc định'}")
    return {
        "message": "Đã bắt đầu quét mạng, kết quả sẽ được cập nhật qua WebSocket.",
        "target": target_range,
    }
