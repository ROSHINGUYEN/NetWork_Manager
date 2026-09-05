"""
MonitorManager - "bộ não" điều phối toàn bộ tác vụ nền của Network Monitor:

  1. _scan_loop        : định kỳ quét thiết bị trong LAN, cập nhật DB, sinh
                          sự kiện (thiết bị mới / online / offline / đổi IP).
  2. _traffic_loop      : định kỳ lấy mẫu tốc độ download/upload, lưu lịch sử
                          trong bộ nhớ + định kỳ ghi xuống SQLite.
  3. _internet_loop     : định kỳ kiểm tra kết nối Internet còn sống hay không.

Tất cả kết quả đều được broadcast realtime qua WebSocket cho dashboard.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from backend.memory_store import MemoryStore
from backend.services import network_info, ping_service, scanner
from backend.services.traffic_monitor import TrafficSampler
from backend.services.websocket_manager import ConnectionManager
from backend.services.security_engine import SecurityEngine
from backend.services.packet_sniffer import PacketSniffer
from backend.services.connection_tracker import ConnectionTracker

logger = logging.getLogger("network_monitor.manager")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class MonitorManager:
    def __init__(self, store: MemoryStore, ws_manager: ConnectionManager, config):
        self.store = store
        self.ws_manager = ws_manager
        self.config = config

        self.device_repo = store.devices
        self.event_repo = store.events
        self.ip_history_repo = store.ip_history
        self.traffic_repo = store.traffic
        self.sec_repo = store.security_events
        self.packet_repo = store.packets
        self.conn_repo = store.connections

        # Khởi tạo Security Services
        self.security_engine = SecurityEngine(self.sec_repo, self.device_repo)
        self.packet_sniffer = PacketSniffer(self.packet_repo, self.security_engine, self.ws_manager)
        self.connection_tracker = ConnectionTracker(self.conn_repo, self.security_engine, self.ws_manager)

        self._traffic_sampler = TrafficSampler()
        self._traffic_history: deque[dict] = deque(maxlen=config.TRAFFIC_HISTORY_SIZE)
        self._traffic_sample_count = 0

        self._internet_status: Optional[str] = None
        self._internet_latency: Optional[float] = None

        gw, iface = network_info.get_default_gateway_and_iface()
        lip, mask = network_info.get_local_ip_and_netmask(iface)
        lmac = network_info.get_local_mac(iface)
        cidr = network_info.compute_cidr(lip, mask)
        self._network_info_cache: dict = {
            "hostname": network_info.get_hostname(),
            "local_ip": lip,
            "netmask": mask,
            "gateway": gw,
            "interface": iface or "Ethernet",
            "mac": lmac,
            "subnet": cidr,
        }
        self._start_time = time.time()

        self._scan_lock = asyncio.Lock()
        self._tasks: list[asyncio.Task] = []
        self._stopping = False

    # ------------------------------------------------------------------ #
    # Vòng đời
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        """Khởi động các vòng lặp nền."""
        self._stopping = False
        await self.security_engine.initialize()
        await self.packet_sniffer.start()
        await self.connection_tracker.start()

        self._tasks = [
            asyncio.create_task(self._scan_loop(), name="scan_loop"),
            asyncio.create_task(self._traffic_loop(), name="traffic_loop"),
            asyncio.create_task(self._internet_loop(), name="internet_loop"),
        ]
        logger.info("MonitorManager: đã khởi động các tác vụ nền (scan/traffic/internet/security).")

    async def stop(self) -> None:
        """Dừng toàn bộ vòng lặp nền một cách an toàn."""
        self._stopping = True
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.packet_sniffer.stop()
        await self.connection_tracker.stop()
        logger.info("MonitorManager: đã dừng toàn bộ tác vụ nền.")

    async def trigger_scan(self, target_range: Optional[str] = None) -> None:
        """Kích hoạt 1 lượt quét ngay lập tức (hỗ trợ chỉ định dải IP tùy biến)."""
        asyncio.create_task(self._run_scan_once(target_range))

    # ------------------------------------------------------------------ #
    # Vòng lặp: quét thiết bị LAN
    # ------------------------------------------------------------------ #

    async def _scan_loop(self) -> None:
        # Quét ngay khi khởi động để dashboard có dữ liệu sớm nhất có thể.
        await asyncio.sleep(1)
        while not self._stopping:
            try:
                await self._run_scan_once()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.exception(f"Lỗi trong vòng lặp quét mạng: {e}")
            await asyncio.sleep(self.config.SCAN_INTERVAL)

    async def _run_scan_once(self, target_range: Optional[str] = None) -> None:
        if self._scan_lock.locked():
            logger.debug("Đang có 1 lượt quét khác chạy, bỏ qua yêu cầu quét mới.")
            return

        async with self._scan_lock:
            gateway_ip, iface = network_info.get_default_gateway_and_iface()
            local_ip, netmask = network_info.get_local_ip_and_netmask(iface)
            local_mac = network_info.get_local_mac(iface)
            cidr = network_info.compute_cidr(local_ip, netmask)
            active_target = target_range.strip() if target_range else cidr

            self._network_info_cache = {
                "hostname": network_info.get_hostname(),
                "local_ip": local_ip,
                "netmask": netmask,
                "gateway": gateway_ip,
                "interface": iface or "Ethernet",
                "mac": local_mac,
                "subnet": active_target,
            }

            logger.info(f"Bắt đầu quét mạng LAN: target={active_target} interface={iface}")
            try:
                results = await scanner.scan_subnet(
                    cidr=active_target,
                    local_ip=local_ip,
                    local_mac=local_mac,
                    max_hosts=self.config.MAX_SCAN_HOSTS,
                    ping_timeout_ms=self.config.PING_TIMEOUT_MS,
                    concurrency=self.config.SCAN_CONCURRENCY,
                    detail_ping_count=self.config.PING_DETAIL_COUNT,
                    scan_ports=True,
                )
            except Exception as e:
                logger.exception(f"Quét mạng thất bại: {e}")
                results = []

            now = _now_iso()
            seen_macs: set[str] = set()
            new_events: list[dict] = []

            for d in results:
                seen_macs.add(d["mac"])
                info = await self.device_repo.upsert_seen(
                    ip=d["ip"],
                    mac=d["mac"],
                    hostname=d["hostname"],
                    vendor=d["vendor"],
                    latency_ms=d["latency_ms"],
                    packet_loss=d["packet_loss"],
                    now=now,
                    open_ports=d.get("open_ports", []),
                    os_name=d.get("os_name", ""),
                    device_type=d.get("device_type", ""),
                )

                # Phân tích an ninh thiết bị (New Device / ARP Spoofing / Suspicious Ports)
                await self.security_engine.analyze_device_discovery(
                    ip=d["ip"], mac=d["mac"], is_new=info["is_new"], open_ports=d.get("open_ports")
                )

                if info["is_new"]:
                    ev = await self.event_repo.add(
                        "new_device", d["mac"], d["ip"],
                        f"Phát hiện thiết bị mới: {d['ip']} ({d['mac']})", now,
                    )
                    new_events.append(ev)
                else:
                    if info["was_offline"]:
                        ev = await self.event_repo.add(
                            "device_online", d["mac"], d["ip"],
                            f"Thiết bị {d['ip']} ({d['mac']}) đã online trở lại", now,
                        )
                        new_events.append(ev)
                    if info["ip_changed"]:
                        await self.ip_history_repo.add(d["mac"], info["old_ip"], d["ip"], now)
                        ev = await self.event_repo.add(
                            "ip_changed", d["mac"], d["ip"],
                            f"Thiết bị {d['mac']} đổi IP từ {info['old_ip']} sang {d['ip']}", now,
                        )
                        new_events.append(ev)

            online_before = await self.device_repo.get_online_macs()
            went_offline = online_before - seen_macs
            if went_offline:
                await self.device_repo.mark_offline(went_offline, now)
                for mac in went_offline:
                    ev = await self.event_repo.add(
                        "device_offline", mac, None, f"Thiết bị {mac} đã offline", now
                    )
                    new_events.append(ev)

            devices = await self.device_repo.get_all()
            await self.ws_manager.broadcast({"type": "devices_update", "data": devices})
            await self.ws_manager.broadcast({"type": "network_update", "data": self.get_network_info()})
            for ev in new_events:
                await self.ws_manager.broadcast({"type": "event", "data": ev})
            await self.ws_manager.broadcast({"type": "stats_update", "data": await self.get_stats()})

            online_count = sum(1 for d in devices if d["status"] == "online")
            logger.info(
                f"Quét hoàn tất: {online_count}/{len(devices)} thiết bị online, "
                f"{len(new_events)} sự kiện mới."
            )

    # ------------------------------------------------------------------ #
    # Vòng lặp: theo dõi băng thông
    # ------------------------------------------------------------------ #

    async def _traffic_loop(self) -> None:
        while not self._stopping:
            try:
                sample = self._traffic_sampler.sample()
                if sample is not None:
                    point = {"timestamp": _now_iso(), **sample}
                    self._traffic_history.append(point)
                    await self.ws_manager.broadcast({"type": "traffic_update", "data": point})

                    self._traffic_sample_count += 1
                    if self._traffic_sample_count % max(self.config.TRAFFIC_PERSIST_EVERY, 1) == 0:
                        await self.traffic_repo.add(
                            timestamp=point["timestamp"],
                            interface=self._network_info_cache.get("interface"),
                            bytes_sent=point["bytes_sent"],
                            bytes_recv=point["bytes_recv"],
                            upload_speed=point["upload_speed"],
                            download_speed=point["download_speed"],
                        )
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.exception(f"Lỗi trong vòng lặp theo dõi traffic: {e}")

            await asyncio.sleep(self.config.TRAFFIC_INTERVAL)

    # ------------------------------------------------------------------ #
    # Vòng lặp: kiểm tra Internet
    # ------------------------------------------------------------------ #

    async def _internet_loop(self) -> None:
        while not self._stopping:
            try:
                result = await ping_service.ping_host(
                    self.config.INTERNET_CHECK_HOST, count=2, timeout_ms=1500
                )
                new_status = "online" if result["alive"] else "offline"
                self._internet_latency = result["latency_ms"]

                if new_status != self._internet_status:
                    if self._internet_status is not None:
                        # Chỉ ghi sự kiện khi có SỰ THAY ĐỔI trạng thái (bỏ qua lần đầu).
                        now = _now_iso()
                        ev = await self.event_repo.add(
                            f"internet_{new_status}",
                            None,
                            self.config.INTERNET_CHECK_HOST,
                            f"Kết nối Internet: {new_status}",
                            now,
                        )
                        await self.ws_manager.broadcast({"type": "event", "data": ev})
                    self._internet_status = new_status

                await self.ws_manager.broadcast(
                    {
                        "type": "internet_update",
                        "data": {"status": self._internet_status, "latency_ms": self._internet_latency},
                    }
                )
                await self.ws_manager.broadcast({"type": "stats_update", "data": await self.get_stats()})
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.exception(f"Lỗi khi kiểm tra kết nối Internet: {e}")

            await asyncio.sleep(self.config.INTERNET_CHECK_INTERVAL)

    # ------------------------------------------------------------------ #
    # Truy vấn trạng thái hiện tại (dùng cho REST API / lúc client mới kết nối WS)
    # ------------------------------------------------------------------ #

    def get_network_info(self) -> dict:
        info = dict(self._network_info_cache)
        info["internet_status"] = self._internet_status
        info["internet_latency_ms"] = self._internet_latency
        return info

    def get_traffic_history(self, limit: Optional[int] = None) -> list[dict]:
        history = list(self._traffic_history)
        if limit:
            return history[-limit:]
        return history

    async def get_stats(self) -> dict:
        devices = await self.device_repo.get_all()
        online = [d for d in devices if d["status"] == "online"]
        latencies = [d["latency_ms"] for d in online if d.get("latency_ms") is not None]
        total_events = await self.event_repo.count()
        current_traffic = self._traffic_history[-1] if self._traffic_history else None

        return {
            "total_devices": len(devices),
            "online_devices": len(online),
            "offline_devices": len(devices) - len(online),
            "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
            "total_events": total_events,
            "internet_status": self._internet_status,
            "internet_latency_ms": self._internet_latency,
            "uptime_seconds": round(time.time() - self._start_time),
            "current_traffic": current_traffic,
            "websocket_clients": self.ws_manager.connection_count,
        }
