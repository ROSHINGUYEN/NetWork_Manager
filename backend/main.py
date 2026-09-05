"""
Network Monitor V1 - Điểm khởi động ứng dụng FastAPI.

Chạy trực tiếp (dev):
    python -m backend.main

Chạy bằng uvicorn (khuyến nghị, kể cả trên Windows):
    uvicorn backend.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.api import devices as devices_api
from backend.api import events as events_api
from backend.api import network as network_api
from backend.api import stats as stats_api
from backend.api import websocket as websocket_api
from backend.api import connections as connections_api
from backend.api import packets as packets_api
from backend.api import security as security_api
from backend.api import lab as lab_api
from backend.config import settings
from backend.logging_config import setup_logging
from backend.memory_store import MemoryStore
from backend.services.monitor_manager import MonitorManager
from backend.services.websocket_manager import ConnectionManager

logger = setup_logging(settings.LOG_LEVEL, settings.LOG_FILE)

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Khởi tạo bộ nhớ RAM tạm thời + bắt đầu các tác vụ nền khi ứng dụng start, dọn dẹp khi shutdown."""
    logger.info("=" * 60)
    logger.info("Đang khởi động Network Monitor (Bộ nhớ tạm RAM - Tắt là quên sạch) ...")
    logger.info("=" * 60)

    store = MemoryStore()
    ws_manager = ConnectionManager()
    monitor = MonitorManager(store, ws_manager, settings)

    app.state.store = store
    app.state.ws_manager = ws_manager
    app.state.monitor = monitor
    app.state.monitor_manager = monitor

    await monitor.start()
    logger.info("Network Monitor đã sẵn sàng phục vụ tại "
                f"http://{settings.HOST}:{settings.PORT}")

    yield

    logger.info("Đang tắt Network Monitor ...")
    await monitor.stop()
    store.close()
    logger.info("Toàn bộ dữ liệu tạm trên RAM đã được giải phóng và xóa sạch. Tạm biệt!")


app = FastAPI(
    title="Network Security Monitor",
    description="Giám sát an ninh mạng LAN, bóc tách gói tin, SOC Alert và Security Lab Mode trong RAM.",
    version="1.3.0",
    lifespan=lifespan,
)

# --- CORS: cho phép dashboard (có thể chạy khác cổng/domain khi dev) gọi API ---
_cors_origins = ["*"] if settings.CORS_ORIGINS.strip() == "*" else [
    o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Routers API + WebSocket ---
app.include_router(network_api.router, tags=["network"])
app.include_router(devices_api.router, tags=["devices"])
app.include_router(events_api.router, tags=["events"])
app.include_router(stats_api.router, tags=["stats"])
app.include_router(websocket_api.router, tags=["websocket"])
app.include_router(connections_api.router, prefix="/api/connections", tags=["connections"])
app.include_router(packets_api.router, prefix="/api/packets", tags=["packets"])
app.include_router(security_api.router, prefix="/api/security", tags=["security"])
app.include_router(lab_api.router)


@app.get("/api/health", tags=["health"])
async def health_check():
    """Endpoint kiểm tra ứng dụng còn sống (dùng cho giám sát/health check)."""
    return {"status": "ok", "service": "network-monitor", "version": "1.0.0"}


# --- Phục vụ giao diện dashboard (HTML/CSS/JS thuần, không cần build step) ---
# Được mount SAU CÙNG (bắt toàn bộ đường dẫn còn lại, bao gồm "/") để các
# route /api/* và /ws/* ở trên luôn được ưu tiên khớp trước.
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
else:
    logger.warning(f"Không tìm thấy thư mục frontend tại {FRONTEND_DIR}, chỉ phục vụ API.")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False,
        log_level=settings.LOG_LEVEL.lower(),
    )
