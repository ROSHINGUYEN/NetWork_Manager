"""
MemoryStore - Bộ nhớ tạm thời thuần Python (Pure Python In-Memory Store).
Hoạt động 100% trên RAM - Không dùng SQLite, không dùng SQL, không ghi bất kỳ byte nào ra ổ đĩa.
Khi tắt ứng dụng hoặc đóng web, toàn bộ dữ liệu thiết bị, IP, kết nối và sự kiện tự động biến mất.
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timezone
from typing import Optional, List, Dict, Set, Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeviceStore:
    """Lưu trữ danh sách thiết bị LAN thuần RAM (Dict theo địa chỉ MAC)."""

    def __init__(self):
        self._devices: Dict[str, dict] = {}
        self._lock = asyncio.Lock()

    async def upsert_seen(
        self,
        ip: str,
        mac: str,
        hostname: str = "",
        vendor: str = "Unknown Vendor",
        latency_ms: Optional[float] = None,
        packet_loss: float = 0.0,
        now: Optional[str] = None,
        open_ports: Optional[List[int]] = None,
        os_name: str = "",
        device_type: str = "",
    ) -> dict:
        now_ts = now or _now_iso()
        mac = mac.upper()
        if open_ports is None:
            open_ports = []

        async with self._lock:
            existing = self._devices.get(mac)
            if not existing:
                dev = {
                    "id": len(self._devices) + 1,
                    "mac": mac,
                    "ip": ip,
                    "hostname": hostname,
                    "vendor": vendor,
                    "status": "online",
                    "latency_ms": latency_ms,
                    "packet_loss": packet_loss,
                    "custom_name": "",
                    "device_type": device_type or "other",
                    "os_name": os_name or "Chưa rõ",
                    "open_ports": open_ports,
                    "first_seen": now_ts,
                    "last_seen": now_ts,
                    "updated_at": now_ts,
                }
                self._devices[mac] = dev
                return {
                    "device": dev.copy(),
                    "is_new": True,
                    "was_offline": False,
                    "ip_changed": False,
                    "old_ip": None,
                }

            # Thiết bị đã từng xuất hiện
            was_offline = (existing["status"] == "offline")
            old_ip = existing["ip"]
            ip_changed = (old_ip != ip)

            existing["ip"] = ip
            if hostname:
                existing["hostname"] = hostname
            if vendor and vendor != "Unknown Vendor":
                existing["vendor"] = vendor
            if os_name and (not existing.get("os_name") or existing.get("os_name") == "Chưa rõ"):
                existing["os_name"] = os_name
            if device_type and (not existing.get("device_type") or existing.get("device_type") == "other"):
                existing["device_type"] = device_type
            existing["status"] = "online"
            if latency_ms is not None:
                existing["latency_ms"] = latency_ms
            existing["packet_loss"] = packet_loss
            if open_ports:
                existing["open_ports"] = open_ports
            existing["last_seen"] = now_ts
            existing["updated_at"] = now_ts

            return {
                "device": existing.copy(),
                "is_new": False,
                "was_offline": was_offline,
                "ip_changed": ip_changed,
                "old_ip": old_ip if ip_changed else None,
            }

    async def get_online_macs(self) -> Set[str]:
        async with self._lock:
            return {d["mac"] for d in self._devices.values() if d["status"] == "online"}

    async def mark_offline(self, macs: Iterable[str], now: Optional[str] = None) -> None:
        now_ts = now or _now_iso()
        macs_upper = {m.upper() for m in macs}
        async with self._lock:
            for mac in macs_upper:
                if mac in self._devices:
                    self._devices[mac]["status"] = "offline"
                    self._devices[mac]["updated_at"] = now_ts

    async def get_by_mac(self, mac: str) -> Optional[dict]:
        mac = mac.upper()
        async with self._lock:
            dev = self._devices.get(mac)
            return dev.copy() if dev else None

    async def get_all(self) -> List[dict]:
        async with self._lock:
            return [d.copy() for d in self._devices.values()]

    async def get_by_status(self, status: str) -> List[dict]:
        async with self._lock:
            return [d.copy() for d in self._devices.values() if d["status"] == status]

    async def update_custom_info(self, mac: str, custom_name: str, device_type: str = "") -> bool:
        mac = mac.upper()
        async with self._lock:
            dev = self._devices.get(mac)
            if not dev:
                return False
            dev["custom_name"] = custom_name
            dev["device_type"] = device_type
            dev["updated_at"] = _now_iso()
            return True

    async def count(self) -> int:
        async with self._lock:
            return len(self._devices)

    async def count_by_status(self, status: str) -> int:
        async with self._lock:
            return sum(1 for d in self._devices.values() if d["status"] == status)


class EventStore:
    """Lưu trữ lịch sử sự kiện mạng trong RAM (tối đa 200 sự kiện mới nhất)."""

    def __init__(self, maxlen: int = 200):
        self._events: deque[dict] = deque(maxlen=maxlen)
        self._seq = 0
        self._lock = asyncio.Lock()

    async def add(self, event_type: str, mac: Optional[str], ip: Optional[str], message: str, created_at: str) -> dict:
        async with self._lock:
            self._seq += 1
            item = {
                "id": self._seq,
                "event_type": event_type,
                "mac": mac or "",
                "ip": ip or "",
                "message": message,
                "created_at": created_at,
            }
            self._events.appendleft(item)
            return item.copy()

    async def list(self, limit: int = 100, offset: int = 0, event_type: Optional[str] = None) -> List[dict]:
        async with self._lock:
            items = list(self._events)

        if event_type:
            items = [e for e in items if e["event_type"] == event_type]

        return [e.copy() for e in items[offset : offset + limit]]

    async def count(self) -> int:
        async with self._lock:
            return len(self._events)


class IpHistoryStore:
    """Lưu trữ lịch sử đổi IP tạm thời trên RAM."""

    def __init__(self, maxlen: int = 100):
        self._history: deque[dict] = deque(maxlen=maxlen)
        self._seq = 0
        self._lock = asyncio.Lock()

    async def add(self, mac: str, old_ip: Optional[str], new_ip: str, changed_at: str) -> dict:
        async with self._lock:
            self._seq += 1
            item = {
                "id": self._seq,
                "mac": mac.upper(),
                "old_ip": old_ip,
                "new_ip": new_ip,
                "changed_at": changed_at,
            }
            self._history.appendleft(item)
            return item.copy()

    async def get_for_mac(self, mac: str, limit: int = 20) -> List[dict]:
        mac = mac.upper()
        async with self._lock:
            items = [h.copy() for h in self._history if h["mac"] == mac]
        return items[:limit]

    async def get_by_mac(self, mac: str, limit: int = 20) -> List[dict]:
        return await self.get_for_mac(mac, limit=limit)


class TrafficStore:
    """Lưu trữ mẫu tốc độ mạng (upload/download) tạm thời trên RAM."""

    def __init__(self, maxlen: int = 200):
        self._samples: deque[dict] = deque(maxlen=maxlen)
        self._seq = 0
        self._lock = asyncio.Lock()

    async def add(
        self,
        timestamp: str,
        interface: Optional[str],
        bytes_sent: int,
        bytes_recv: int,
        upload_speed: float,
        download_speed: float,
    ) -> None:
        async with self._lock:
            self._seq += 1
            item = {
                "id": self._seq,
                "timestamp": timestamp,
                "interface": interface or "",
                "bytes_sent": bytes_sent,
                "bytes_recv": bytes_recv,
                "upload_speed": upload_speed,
                "download_speed": download_speed,
            }
            self._samples.append(item)

    async def get_recent(self, limit: int = 200) -> List[dict]:
        async with self._lock:
            items = list(self._samples)
        return [s.copy() for s in items[-limit:]]


class SecurityEventStore:
    """Lưu trữ cảnh báo an ninh tạm thời trên RAM (tối đa 100 cảnh báo)."""

    def __init__(self, maxlen: int = 100):
        self._events: deque[dict] = deque(maxlen=maxlen)
        self._seq = 0
        self._lock = asyncio.Lock()

    async def add(
        self,
        severity: int,
        threat_category: str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        details: str,
        created_at: str,
    ) -> dict:
        async with self._lock:
            self._seq += 1
            item = {
                "id": self._seq,
                "severity": severity,
                "threat_category": threat_category,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "details": details,
                "created_at": created_at,
            }
            self._events.appendleft(item)
            return item.copy()

    async def get_recent(self, limit: int = 100) -> List[dict]:
        async with self._lock:
            items = list(self._events)
        return [e.copy() for e in items[:limit]]


class ConnectionStore:
    """Lưu trữ các socket kết nối tạm thời trên RAM (tối đa 150 socket mới nhất)."""

    def __init__(self, maxlen: int = 150):
        self._conns: deque[dict] = deque(maxlen=maxlen)
        self._seq = 0
        self._lock = asyncio.Lock()

    async def add(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        status: str,
        pid: Optional[int],
        process_name: Optional[str],
        is_suspicious: int,
        threat_info: str,
        timestamp: str,
        service_name: str = "",
    ) -> None:
        async with self._lock:
            self._seq += 1
            item = {
                "id": self._seq,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "service_name": service_name or "",
                "status": status,
                "pid": pid,
                "process_name": process_name or "",
                "is_suspicious": is_suspicious,
                "threat_info": threat_info,
                "timestamp": timestamp,
            }
            self._conns.appendleft(item)

    async def get_recent(self, limit: int = 100) -> List[dict]:
        async with self._lock:
            items = list(self._conns)
        return [c.copy() for c in items[:limit]]

    async def clear_old(self, keep_latest: int = 100) -> None:
        pass


class PacketStore:
    """Lưu trữ gói tin bóc tách gần nhất trên RAM (tối đa 150 gói tin)."""

    def __init__(self, maxlen: int = 150):
        self._packets: deque[dict] = deque(maxlen=maxlen)
        self._seq = 0
        self._lock = asyncio.Lock()

    async def add(
        self,
        timestamp: str,
        protocol: str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        packet_size: int,
        tcp_flags: str,
        info: str,
        is_anomaly: int,
    ) -> None:
        async with self._lock:
            self._seq += 1
            item = {
                "id": self._seq,
                "timestamp": timestamp,
                "protocol": protocol,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "packet_size": packet_size,
                "tcp_flags": tcp_flags,
                "info": info,
                "is_anomaly": is_anomaly,
            }
            self._packets.appendleft(item)

    async def get_recent(self, limit: int = 100) -> List[dict]:
        async with self._lock:
            items = list(self._packets)
        return [p.copy() for p in items[:limit]]

    async def clear_old(self, keep_latest: int = 100) -> None:
        pass


class MemoryStore:
    """Tập hợp toàn bộ bộ nhớ tạm thời của hệ thống (Pure Python In-Memory Store)."""

    def __init__(self):
        self.devices = DeviceStore()
        self.events = EventStore()
        self.ip_history = IpHistoryStore()
        self.traffic = TrafficStore()
        self.security_events = SecurityEventStore()
        self.connections = ConnectionStore()
        self.packets = PacketStore()

    def close(self):
        """Giải phóng toàn bộ bộ nhớ khi tắt web."""
        self.devices._devices.clear()
        self.events._events.clear()
        self.ip_history._history.clear()
        self.traffic._samples.clear()
        self.security_events._events.clear()
        self.connections._conns.clear()
        self.packets._packets.clear()
