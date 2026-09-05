"""
Thiết lập hệ thống logging tập trung cho toàn bộ ứng dụng.
Mặc định hoạt động ở chế độ Zero-Disk-Footprint: chỉ xuất log ra console,
không tạo bất kỳ file hay thư mục log nào trên ổ đĩa.
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path
from typing import Optional


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Cấu hình logger gốc 'network_monitor' dùng chung cho toàn bộ backend."""
    root_logger = logging.getLogger("network_monitor")
    root_logger.setLevel(log_level.upper())
    root_logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Xoá handler cũ nếu setup_logging được gọi lại
    root_logger.handlers.clear()

    # Luôn xuất log ra Console / Terminal
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Chỉ ghi file nếu được chỉ định rõ (mặc định là None - không ghi file rác)
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                filename=str(log_path),
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except OSError as e:
            root_logger.warning(f"Không thể tạo file log tại {log_file}: {e}")

    # Giảm độ ồn của các thư viện bên thứ ba
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    return root_logger
