"""
Cấu hình ứng dụng - Kiến trúc Zero-Disk-Footprint & In-Memory.
Không cần file .env, không ghi database ra đĩa (100% RAM :memory:),
không tạo file log rác. Mọi tham số đều có giá trị mặc định tối ưu sẵn sàng chạy ngay.
"""

from __future__ import annotations

import os
from typing import Optional


class Settings:
    """Tập hợp toàn bộ cấu hình mặc định của Network Monitor."""

    # --- Máy chủ web ---
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    # --- Bộ nhớ lưu trữ: Thuần RAM (Pure Python In-Memory) ---
    # Tắt ứng dụng là giải phóng RAM, quên sạch, không lưu bất kỳ file nào ra đĩa

    # --- Quét mạng LAN ---
    SCAN_INTERVAL: int = int(os.getenv("SCAN_INTERVAL", "30"))
    PING_TIMEOUT_MS: int = int(os.getenv("PING_TIMEOUT_MS", "1000"))
    MAX_SCAN_HOSTS: int = int(os.getenv("MAX_SCAN_HOSTS", "254"))
    SCAN_CONCURRENCY: int = int(os.getenv("SCAN_CONCURRENCY", "60"))
    PING_DETAIL_COUNT: int = int(os.getenv("PING_DETAIL_COUNT", "2"))

    # --- Theo dõi băng thông ---
    TRAFFIC_INTERVAL: float = float(os.getenv("TRAFFIC_INTERVAL", "2"))
    TRAFFIC_PERSIST_EVERY: int = int(os.getenv("TRAFFIC_PERSIST_EVERY", "5"))
    TRAFFIC_HISTORY_SIZE: int = int(os.getenv("TRAFFIC_HISTORY_SIZE", "150"))

    # --- Kiểm tra kết nối Internet ---
    INTERNET_CHECK_INTERVAL: int = int(os.getenv("INTERNET_CHECK_INTERVAL", "15"))
    INTERNET_CHECK_HOST: str = os.getenv("INTERNET_CHECK_HOST", "8.8.8.8")

    # --- Logging: Xuất ra Console, không tạo file log rác trên ổ cứng ---
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: Optional[str] = os.getenv("LOG_FILE", None)

    # --- CORS ---
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "*")


settings = Settings()
