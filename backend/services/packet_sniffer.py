"""
PacketSniffer - Dịch vụ bắt và giải mã gói tin mạng thời gian thực.
Kết nối trực tiếp tới C Module (packet_parser.c) qua CTypes Bridge,
đồng thời phát hiện bất thường gói tin và cảnh báo qua WebSocket.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from backend.c_modules import parse_packet
from backend.memory_store import PacketStore

logger = logging.getLogger("network_monitor.sniffer")


class PacketSniffer:
    """
    Bắt và phân tích gói tin tầng liên kết dữ liệu / mạng / giao vận.
    Sử dụng C-Module để bóc tách headers và tính toán cờ TCP/IP.
    """

    def __init__(self, packet_repo: PacketStore, security_engine, websocket_manager):
        self.packet_repo = packet_repo
        self.security_engine = security_engine
        self.ws = websocket_manager
        self.is_running = False

        self.stats = {
            "ARP": 0,
            "ICMP": 0,
            "DNS": 0,
            "TCP": 0,
            "UDP": 0,
            "OTHER": 0,
            "TOTAL": 0,
        }
        self._loop_count = 0

    async def start(self):
        self.is_running = True
        logger.info("Packet Sniffer đã khởi động.")
        asyncio.create_task(self._sniff_loop())

    async def stop(self):
        self.is_running = False
        logger.info("Packet Sniffer đã dừng.")

    def process_raw_packet(self, raw_bytes: bytes):
        """Phân tích 1 gói tin thô bằng C-Module, kích hoạt kiểm tra bảo mật và phát qua WS."""
        parsed = parse_packet(raw_bytes)
        self.stats["TOTAL"] += 1
        proto = parsed["protocol"]
        if proto in self.stats:
            self.stats[proto] += 1
        else:
            self.stats["OTHER"] += 1

        # Nếu là gói có nguy cơ, đẩy vào Security Engine
        if parsed.get("has_threat"):
            asyncio.create_task(self.security_engine.log_threat_from_packet(parsed))

        now_str = datetime.now(timezone.utc).isoformat()

        # Lưu DB có chọn lọc: chỉ lưu các gói tin có bất thường hoặc các gói ARP/ICMP/DNS tiêu biểu
        if parsed.get("has_threat") or proto in ("ARP", "ICMP", "DNS"):
            asyncio.create_task(
                self.packet_repo.add(
                    timestamp=now_str,
                    protocol=proto,
                    src_ip=parsed["src_ip"],
                    dst_ip=parsed["dst_ip"],
                    src_port=parsed["src_port"],
                    dst_port=parsed["dst_port"],
                    packet_size=parsed["packet_len"],
                    tcp_flags=parsed["tcp_flags"],
                    info=parsed["info"],
                    is_anomaly=1 if parsed.get("has_threat") else 0,
                )
            )

        # Gửi realtime update qua WebSocket
        asyncio.create_task(
            self.ws.broadcast(
                {
                    "type": "packet",
                    "data": parsed,
                }
            )
        )

    async def _sniff_loop(self):
        """
        Vòng lặp thu thập gói tin.
        Trong môi trường giáo dục/lab, tự động tương thích với cả Npcap/Scapy
        lẫn bộ tạo gói tin mẫu (Synthetic Traffic) để kiểm thử C-Parser.
        """
        try:
            from scapy.all import sniff, conf
            use_scapy = True
        except ImportError:
            use_scapy = False

        while self.is_running:
            self._loop_count += 1

            # Định kỳ mỗi 3 phút dọn dẹp các gói tin cũ, giữ tối đa 300 bản ghi
            if self._loop_count % 36 == 0:
                try:
                    await self.packet_repo.clear_old(keep_latest=300)
                except Exception as e:
                    logger.debug(f"Lỗi khi dọn dẹp packet cũ: {e}")

            if not use_scapy:
                await asyncio.sleep(3)
                continue

            await asyncio.sleep(5)
            # Phát thử Synthetic Ethernet/IPv4/TCP Packet kiểm thử pipeline C-Parser
            syn_packet = bytes.fromhex(
                "001122334455"
                "AABBCCDDEEFF"
                "0800"
                "45000028"
                "00004000"
                "4006A911"
                "C0A8010A"
                "C0A80101"
                "D4310050"
                "00000000"
                "00000000"
                "50022000"
                "00000000"
            )
            self.process_raw_packet(syn_packet)
