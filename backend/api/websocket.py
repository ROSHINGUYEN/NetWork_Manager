"""
Endpoint WebSocket /ws/dashboard

Khi client (dashboard) kết nối:
  1. Server gửi ngay 1 "snapshot" đầy đủ dữ liệu hiện tại (devices, network,
     stats) để giao diện hiển thị được ngay, không cần chờ chu kỳ quét kế tiếp.
  2. Sau đó server tiếp tục đẩy các bản tin cập nhật realtime
     (devices_update, network_update, traffic_update, internet_update, event)
     mỗi khi có dữ liệu mới từ MonitorManager.
"""

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger("network_monitor.api.websocket")
router = APIRouter()


@router.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    ws_manager = websocket.app.state.ws_manager
    monitor = websocket.app.state.monitor

    await ws_manager.connect(websocket)

    try:
        # Gửi snapshot ban đầu ngay khi kết nối
        devices = await monitor.device_repo.get_all()
        await websocket.send_json({"type": "devices_update", "data": devices})
        await websocket.send_json({"type": "network_update", "data": monitor.get_network_info()})
        await websocket.send_json({"type": "traffic_history", "data": monitor.get_traffic_history(limit=60)})
        stats = await monitor.get_stats()
        await websocket.send_json({"type": "stats_update", "data": stats})

        # Giữ kết nối, lắng nghe tin nhắn từ client (vd: "ping" giữ kết nối).
        # Không yêu cầu client phải gửi gì, chỉ cần chờ để phát hiện disconnect.
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"Kết nối WebSocket gặp lỗi: {e}")
        await ws_manager.disconnect(websocket)
