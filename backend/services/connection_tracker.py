"""
ConnectionTracker - Giám sát các kết nối mạng TCP/UDP thời gian thực trên máy host.
Phát hiện kết nối ra ngoài cổng bất thường, nhận diện tiến trình (PID/Process Name),
phát cảnh báo qua WebSocket và lưu trữ các kết nối an ninh đáng chú ý vào SQLite.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
import psutil

from backend.memory_store import ConnectionStore

logger = logging.getLogger("network_monitor.connection_tracker")


PORT_MAP = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    587: "SMTP-Sub",
    465: "SMTPS",
    110: "POP3",
    995: "POP3S",
    143: "IMAP",
    993: "IMAPS",
    445: "SMB (File Share)",
    135: "MS-RPC",
    139: "NetBIOS",
    3389: "RDP (Remote Desktop)",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8000: "FastAPI / Web App",
    1900: "SSDP / UPnP",
    5353: "mDNS",
    554: "RTSP (Camera)",
    123: "NTP",
    4444: "Suspicious C2 / Shell",
    6667: "IRC",
}


def port_to_service(port: int) -> str:
    return PORT_MAP.get(port, f"Port {port}")


class ConnectionTracker:
    """Theo dõi các kết nối TCP/UDP đang hoạt động trên máy."""

    def __init__(self, conn_repo: ConnectionStore, security_engine, websocket_manager):
        self.conn_repo = conn_repo
        self.security_engine = security_engine
        self.ws = websocket_manager
        self.is_running = False

        # Cổng thường bị mã độc, botnet hoặc dịch vụ nhạy cảm lợi dụng
        self.suspicious_ports = {6667, 3333, 4444, 445, 3389, 5900, 135, 139, 23, 21}
        self._loop_count = 0

    async def start(self):
        self.is_running = True
        logger.info("Connection Tracker đã khởi động.")
        asyncio.create_task(self._track_loop())

    async def stop(self):
        self.is_running = False
        logger.info("Connection Tracker đã dừng.")

    async def _track_loop(self):
        while self.is_running:
            try:
                conns = psutil.net_connections(kind="all")
                active_list = []
                now_str = datetime.now(timezone.utc).isoformat()
                self._loop_count += 1

                for c in conns:
                    if not c.raddr:
                        continue  # Chỉ theo dõi các socket có địa chỉ đích (ESTABLISHED/SYN_SENT/...)

                    src_ip = c.laddr.ip
                    src_port = c.laddr.port
                    dst_ip = c.raddr.ip
                    dst_port = c.raddr.port

                    # Bỏ qua lưu lượng loopback nội bộ
                    if src_ip in ("127.0.0.1", "::1") and dst_ip in ("127.0.0.1", "::1"):
                        continue

                    is_susp = 0
                    threat_info = ""

                    # Phát hiện kết nối đến cổng nhạy cảm / nguy hiểm
                    if dst_port in self.suspicious_ports:
                        is_susp = 1
                        threat_info = f"Cảnh báo kết nối ra ngoài đến cổng nguy hiểm: {dst_port}"

                    # Lấy tên tiến trình sở hữu socket
                    pname = ""
                    if c.pid:
                        try:
                            p = psutil.Process(c.pid)
                            pname = p.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pname = "unknown"

                    proto_str = "TCP" if c.type == 1 else ("UDP" if c.type == 2 else "OTHER")
                    svc_name = PORT_MAP.get(dst_port) or PORT_MAP.get(src_port) or f"{proto_str}-{dst_port}"

                    c_data = {
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": proto_str,
                        "service_name": svc_name,
                        "status": c.status,
                        "pid": c.pid,
                        "process_name": pname,
                        "is_suspicious": is_susp,
                        "threat_info": threat_info,
                        "timestamp": now_str,
                    }
                    active_list.append(c_data)

                    # Tối ưu lưu DB: Chỉ ghi các kết nối đáng ngờ, hoặc định kỳ mỗi 6 chu kỳ (30s)
                    # lấy mẫu 1 số kết nối đại diện để tránh spam phình to database SQLite.
                    if is_susp or (self._loop_count % 6 == 0 and len(active_list) <= 15):
                        await self.conn_repo.add(**c_data)

                # Định kỳ mỗi 3 phút dọn dẹp các kết nối cũ, giữ tối đa 300 bản ghi mới nhất
                if self._loop_count % 36 == 0:
                    await self.conn_repo.clear_old(keep_latest=300)

                # Gửi danh sách socket hoạt động tức thời lên dashboard qua WebSocket
                if active_list:
                    await self.ws.broadcast(
                        {
                            "type": "connections_update",
                            "data": active_list[:100],  # Giới hạn 100 kết nối để UI mượt mà
                        }
                    )

            except Exception as e:
                logger.error(f"Lỗi khi theo dõi kết nối mạng: {e}")

            await asyncio.sleep(5)
