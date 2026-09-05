"""
Service quét thiết bị trong mạng LAN nội bộ.

Chiến lược quét nhiều tầng (Layered Scanning - tham khảo kiến trúc myNetwork):
  1. Hỗ trợ nhập dải IP linh hoạt (CIDR: 192.168.1.0/24, Dash: 192.168.1.1-192.168.1.50, hoặc danh sách phân tách dấu phẩy).
  2. Ping đồng thời (giới hạn concurrency) toàn bộ IP trong dải để đánh thức và điền vào bảng ARP của hệ điều hành.
  3. Đọc bảng ARP hệ thống để lấy ánh xạ IP -> MAC.
  4. Với mỗi host online: tra cứu hostname, tra cứu vendor OUI, đo ping chi tiết và quét nhanh Top Ports (80, 443, 53, 22, 445, 8080, 8443, 8000...).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Optional

from backend.services import ping_service, vendor_lookup

logger = logging.getLogger("network_monitor.scanner")

# Danh mục các cổng dịch vụ phổ biến nhất trên thiết bị LAN
POPULAR_PORTS = [80, 443, 53, 22, 445, 8080, 8443, 8000, 554, 3389]


def parse_target_hosts(target: str, max_hosts: int = 254) -> list[str]:
    """
    Phân tích chuỗi dải IP linh hoạt thành danh sách địa chỉ IP cụ thể:
      - CIDR: '192.168.1.0/24'
      - Dải dấu gạch nối: '192.168.1.1-192.168.1.50'
      - Phân tách bằng dấu phẩy: '192.168.1.1, 192.168.1.2'
      - IP đơn lẻ: '192.168.1.1'
    """
    target = target.strip()
    hosts = []

    # Trường hợp nhiều dải phân tách bằng dấu phẩy
    if "," in target:
        for part in target.split(","):
            hosts.extend(parse_target_hosts(part.strip(), max_hosts=max_hosts))
        return list(dict.fromkeys(hosts))[:max_hosts]

    # Trường hợp dạng dải bắt đầu - kết thúc: 192.168.1.1-192.168.1.50 hoặc 192.168.1.1-50
    if "-" in target:
        try:
            start_str, end_str = target.split("-", 1)
            start_ip = ipaddress.IPv4Address(start_str.strip())
            if "." in end_str:
                end_ip = ipaddress.IPv4Address(end_str.strip())
            else:
                # Dạng rút gọn: 192.168.1.1-50
                octets = start_str.strip().split(".")
                octets[-1] = end_str.strip()
                end_ip = ipaddress.IPv4Address(".".join(octets))

            cur = int(start_ip)
            end = int(end_ip)
            if cur <= end:
                for val in range(cur, end + 1):
                    hosts.append(str(ipaddress.IPv4Address(val)))
                    if len(hosts) >= max_hosts:
                        break
                return hosts
        except Exception as e:
            logger.warning(f"Không phân tích được dải gạch nối '{target}': {e}")

    # Trường hợp CIDR: 192.168.1.0/24
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            hosts = [str(h) for h in net.hosts()]
            return hosts[:max_hosts]
        except Exception as e:
            logger.warning(f"Không phân tích được CIDR '{target}': {e}")

    # Trường hợp IP đơn lẻ
    try:
        ipaddress.IPv4Address(target)
        return [target]
    except Exception:
        pass

    # Nếu không khớp định dạng nào, thử coi là CIDR /24
    try:
        net = ipaddress.ip_network(f"{target}/24", strict=False)
        return [str(h) for h in net.hosts()][:max_hosts]
    except Exception:
        logger.error(f"Dải mạng mục tiêu không hợp lệ: '{target}'")
        return []


async def _probe_single_port(ip: str, port: int, timeout: float = 0.25) -> Optional[int]:
    """Kiểm tra nhanh 1 cổng TCP bằng non-blocking socket connect."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None


async def scan_popular_ports(ip: str) -> list[int]:
    """Quét đồng thời Top 10 cổng phổ biến nhất của 1 IP trong LAN."""
    tasks = [_probe_single_port(ip, p) for p in POPULAR_PORTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [p for p in results if isinstance(p, int)]


def infer_device_os_and_type(
    ttl: Optional[int],
    open_ports: list[int],
    vendor: str,
    hostname: str,
    ip: str,
) -> tuple[str, str]:
    """
    Suy luận hệ điều hành (OS) và loại thiết bị từ TTL, Open Ports, Vendor OUI và Hostname.
    Trả về: (os_name, device_type)
    """
    v_lower = (vendor or "").lower()
    h_lower = (hostname or "").lower()
    ports_set = set(open_ports or [])

    # 1. Router / Gateway
    if ip.endswith(".1") or any(r in v_lower for r in ["zte", "draytek", "cisco", "huawei router", "tp-link", "mikrotik"]):
        return "RouterOS / Linux Embedded", "router"

    # 2. Camera IP
    if 554 in ports_set or any(c in v_lower for c in ["hikvision", "ezviz", "dahua", "imou"]) or "cam" in h_lower:
        return "Embedded Linux (IP Camera)", "camera"

    # 3. Linux Server / Host (SSH / NFS / Web / Ubuntu / Debian hostname)
    if ports_set.intersection({22, 111, 2049, 9090}) or any(l in h_lower for l in ["ubuntu", "debian", "linux", "centos", "arch"]):
        return "Linux (Ubuntu/Debian)", "pc"

    # 4. Windows PC / Server (SMB, NetBIOS, RDP, WSD, Windows hostname or TTL 128)
    if ports_set.intersection({135, 139, 445, 3389, 5357}) or "win" in h_lower or "desktop" in h_lower or (ttl is not None and ttl > 64 and ttl <= 128):
        return "Windows 10/11", "pc"

    # 5. Apple iOS / macOS
    if "apple" in v_lower or ports_set.intersection({548, 5000, 7000, 62078}) or "iphone" in h_lower or "ipad" in h_lower or "macbook" in h_lower:
        if "iphone" in h_lower or "ipad" in h_lower:
            return "Apple iOS", "phone"
        return "Apple macOS", "pc" if "mac" in h_lower else "phone"

    # 6. Mobile Android
    if any(m in v_lower for m in ["samsung", "xiaomi", "oppo", "vivo", "motorola", "oneplus"]) or 5555 in ports_set or "android" in h_lower or "galaxy" in h_lower:
        return "Android OS", "phone"

    # 7. Smart TV / Box
    if any(t in v_lower for t in ["sony", "lg", "tcl", "roku"]) or any(t in h_lower for t in ["tv", "box", "cast"]):
        return "Android TV / webOS", "tv"

    # 8. IoT / Smart Home
    if any(i in v_lower for i in ["tuya", "espressif", "sonoff", "dragon technology"]) or any(i in h_lower for i in ["iot", "switch", "plug", "sensor"]):
        return "FreeRTOS / Embedded IoT", "iot"

    # 9. Hardware PC vendor fallback
    if any(w in v_lower for w in ["realtek", "intel", "dell", "hp", "lenovo", "asus", "gigabyte", "msi"]) or "pc" in h_lower:
        if ttl is not None and ttl <= 64:
            return "Linux / Unix PC", "pc"
        return "Windows 10/11", "pc"

    # 9. Fallback theo giá trị TTL ping
    if ttl is not None:
        if ttl <= 64:
            return "Linux / Android / iOS (TTL 64)", "other"
        elif ttl <= 128:
            return "Windows (TTL 128)", "pc"
        else:
            return "Router / Network Device (TTL 255)", "router"

    return "Chưa rõ (Generic OS)", "other"


async def scan_subnet(
    cidr: str,
    local_ip: str,
    local_mac: str,
    max_hosts: int = 254,
    ping_timeout_ms: int = 1000,
    concurrency: int = 60,
    detail_ping_count: int = 2,
    scan_ports: bool = True,
) -> list[dict]:
    """
    Quét toàn bộ thiết bị đang online trong dải mạng `cidr`.
    Hỗ trợ dải CIDR, range gạch nối hoặc IP đơn lẻ.
    """
    hosts = parse_target_hosts(cidr, max_hosts=max_hosts)
    if not hosts:
        logger.warning(f"Không có host nào để quét trong mục tiêu '{cidr}'")
        return []

    semaphore = asyncio.Semaphore(concurrency)

    async def _ping_one(ip: str) -> dict:
        async with semaphore:
            return await ping_service.ping_host(ip, count=1, timeout_ms=ping_timeout_ms)

    logger.info(f"Đang ping quét {len(hosts)} host trong dải mạng {cidr}...")
    ping_results = await asyncio.gather(*[_ping_one(ip) for ip in hosts])
    alive_hosts: dict[str, dict] = {r["ip"]: r for r in ping_results if r["alive"]}

    # Đảm bảo chính máy đang chạy chương trình luôn xuất hiện nếu thuộc dải quét
    if local_ip in hosts and local_ip not in alive_hosts:
        alive_hosts[local_ip] = {
            "ip": local_ip,
            "alive": True,
            "latency_ms": 1.0,
            "packet_loss": 0.0,
            "ttl": 128,
        }

    arp_table = await ping_service.get_arp_table()

    devices: list[dict] = []
    hostname_tasks = []
    detail_ping_tasks = []
    port_tasks = []
    host_ips = []

    for ip, ping_info in alive_hosts.items():
        mac = arp_table.get(ip)
        if not mac and ip == local_ip:
            mac = local_mac
        if not mac:
            logger.debug(f"Bỏ qua {ip}: không xác định được MAC.")
            continue

        host_ips.append((ip, mac))
        hostname_tasks.append(ping_service.resolve_hostname(ip))
        detail_ping_tasks.append(
            ping_service.ping_host(ip, count=detail_ping_count, timeout_ms=ping_timeout_ms)
        )
        if scan_ports:
            port_tasks.append(scan_popular_ports(ip))

    hostnames = await asyncio.gather(*hostname_tasks) if hostname_tasks else []
    detail_results = await asyncio.gather(*detail_ping_tasks) if detail_ping_tasks else []
    open_ports_results = await asyncio.gather(*port_tasks) if port_tasks else [[] for _ in host_ips]

    for (ip, mac), hostname, detail, ports in zip(host_ips, hostnames, detail_results, open_ports_results):
        vendor = vendor_lookup.lookup_vendor(mac)
        ttl = detail.get("ttl")
        port_list = ports if isinstance(ports, list) else []
        os_name, dev_type = infer_device_os_and_type(ttl, port_list, vendor, hostname, ip)

        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "latency_ms": detail.get("latency_ms"),
                "packet_loss": detail.get("packet_loss", 0.0),
                "open_ports": port_list,
                "ttl": ttl,
                "os_name": os_name,
                "device_type": dev_type,
            }
        )

    logger.info(f"Quét xong: phát hiện {len(devices)} thiết bị online trong {cidr}.")
    return devices
