"""
Service theo dõi lưu lượng mạng (download/upload) của toàn bộ máy chủ,
dựa trên bộ đếm byte lũy kế của hệ điều hành (psutil.net_io_counters).

Tốc độ tức thời được tính bằng cách lấy hiệu số byte giữa 2 lần lấy mẫu
liên tiếp chia cho khoảng thời gian trôi qua.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger("network_monitor.traffic")


class TrafficSampler:
    """Giữ trạng thái lần lấy mẫu trước đó để tính tốc độ tức thời."""

    def __init__(self):
        self._last_counters: Optional[tuple] = None  # (counters, timestamp)

    def sample(self) -> Optional[dict]:
        """
        Lấy 1 mẫu tốc độ mạng hiện tại.

        Trả về None ở lần gọi đầu tiên (chưa có mốc so sánh), các lần sau
        trả về dict {bytes_sent, bytes_recv, upload_speed, download_speed}
        (đơn vị speed: byte/giây).
        """
        if psutil is None:
            return None
        try:
            counters = psutil.net_io_counters()
        except Exception as e:
            logger.error(f"Không đọc được thống kê mạng từ psutil: {e}")
            return None

        now = time.time()

        if self._last_counters is None:
            self._last_counters = (counters, now)
            return None

        prev_counters, prev_time = self._last_counters
        elapsed = max(now - prev_time, 0.001)

        upload_speed = max((counters.bytes_sent - prev_counters.bytes_sent) / elapsed, 0.0)
        download_speed = max((counters.bytes_recv - prev_counters.bytes_recv) / elapsed, 0.0)

        self._last_counters = (counters, now)

        return {
            "bytes_sent": counters.bytes_sent,
            "bytes_recv": counters.bytes_recv,
            "upload_speed": round(upload_speed, 2),
            "download_speed": round(download_speed, 2),
        }
