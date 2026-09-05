"""
Service xác định thông tin mạng cục bộ của máy đang chạy chương trình:
địa chỉ IP, subnet mask, cổng mặc định (gateway), tên network interface
và địa chỉ MAC của chính máy đó.

Toàn bộ dữ liệu này lấy từ cấu hình hệ điều hành (routing table / network
interface), KHÔNG gửi bất kỳ gói tin nào ra Internet để xác định.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import uuid
from typing import Optional

try:
    import netifaces
except ImportError:  # pragma: no cover - netifaces luôn có trong requirements
    netifaces = None

logger = logging.getLogger("network_monitor.network_info")


def get_default_gateway_and_iface() -> tuple[Optional[str], Optional[str]]:
    """Trả về (gateway_ip, interface_name) của tuyến đường mặc định (IPv4)."""
    if netifaces is not None:
        try:
            gateways = netifaces.gateways()
            default = gateways.get("default", {})
            if netifaces.AF_INET in default:
                gateway_ip, iface = default[netifaces.AF_INET]
                return gateway_ip, iface
        except Exception as e:
            logger.debug(f"Không lấy được gateway qua netifaces: {e}")

    # Fallback cho Windows: đọc bảng định tuyến bằng lệnh route print 0.0.0.0
    import platform
    import subprocess
    if platform.system().lower() == "windows":
        try:
            output = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                timeout=3,
            ).decode(errors="ignore")
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0":
                    gateway_ip = parts[2]
                    return gateway_ip, "Ethernet"
        except Exception as e:
            logger.debug(f"Lệnh route print đọc gateway thất bại: {e}")

    logger.warning("Không xác định được gateway mặc định.")
    return None, None


def get_local_ip_and_netmask(iface: Optional[str]) -> tuple[str, str]:
    """Trả về (local_ip, netmask) của interface đang dùng để ra ngoài mạng."""
    if netifaces is not None and iface:
        try:
            addrs = netifaces.ifaddresses(iface)
            inet_list = addrs.get(netifaces.AF_INET)
            if inet_list:
                info = inet_list[0]
                ip = info.get("addr")
                netmask = info.get("netmask") or "255.255.255.0"
                if ip:
                    return ip, netmask
        except Exception as e:
            logger.debug(f"Không lấy được IP/netmask qua netifaces cho '{iface}': {e}")

    # Phương án dự phòng: mở 1 socket UDP "connect" tới 8.8.8.8:80.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip, "255.255.255.0"
    except Exception as e:
        logger.error(f"Không xác định được local IP, dùng giá trị mặc định 127.0.0.1: {e}")
        return "127.0.0.1", "255.255.255.0"


def get_local_mac(iface: Optional[str]) -> str:
    """Trả về địa chỉ MAC (dạng AA:BB:CC:DD:EE:FF) của interface chính."""
    if netifaces is not None and iface:
        try:
            addrs = netifaces.ifaddresses(iface)
            link_list = addrs.get(netifaces.AF_LINK)
            if link_list and link_list[0].get("addr"):
                return link_list[0]["addr"].upper().replace("-", ":")
        except Exception as e:
            logger.debug(f"Không lấy được MAC qua netifaces cho '{iface}': {e}")

    # Fallback cho Windows: lấy MAC adapter qua getmac
    import platform
    import subprocess
    if platform.system().lower() == "windows":
        try:
            out = subprocess.check_output(
                ["getmac", "/fo", "csv", "/nh"],
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                timeout=3,
            ).decode(errors="ignore")
            for line in out.splitlines():
                line = line.strip().strip('"')
                if line and "disconnected" not in line.lower():
                    mac_part = line.split('","')[0].replace('"', '').strip()
                    if len(mac_part) == 17:
                        return mac_part.upper().replace("-", ":")
        except Exception as e:
            logger.debug(f"Lệnh getmac thất bại: {e}")

    # Phương án dự phòng cuối: uuid.getnode()
    try:
        mac_int = uuid.getnode()
        return ":".join(f"{(mac_int >> shift) & 0xFF:02X}" for shift in range(40, -8, -8))
    except Exception:
        return "00:00:00:00:00:00"


def compute_cidr(ip: str, netmask: str) -> str:
    """Tính dải mạng CIDR (vd 192.168.1.0/24) từ IP + subnet mask."""
    try:
        network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except Exception as e:
        logger.warning(f"Không tính được CIDR từ {ip}/{netmask} ({e}), dùng /24 mặc định.")
        try:
            octets = ip.split(".")
            return ".".join(octets[:3]) + ".0/24"
        except Exception:
            return "192.168.1.0/24"


def get_hostname() -> str:
    """Trả về hostname của chính máy đang chạy chương trình."""
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"


def list_all_interfaces() -> list[dict]:
    """Liệt kê toàn bộ network interface có IPv4 trên máy (phục vụ chẩn đoán)."""
    result: list[dict] = []
    if netifaces is None:
        return result
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            inet_list = addrs.get(netifaces.AF_INET, [])
            for info in inet_list:
                result.append(
                    {
                        "interface": iface,
                        "ip": info.get("addr"),
                        "netmask": info.get("netmask"),
                    }
                )
    except Exception as e:
        logger.warning(f"Không liệt kê được danh sách interface: {e}")
    return result


async def lookup_isp_info() -> dict:
    """
    Tra cứu thông tin nhà mạng (ISP), số hiệu ASN và Public IP.
    CHỈ thực hiện khi người dùng chủ động cho phép (Opt-in).
    """
    import asyncio
    import json
    import urllib.request
    from datetime import datetime

    def _sync_fetch() -> dict:
        url = "http://ip-api.com/json/?fields=status,message,country,city,isp,as,query"
        req = urllib.request.Request(url, headers={"User-Agent": "NetworkSecurityMonitor/1.3"})
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            return json.loads(resp.read().decode("utf-8"))

    try:
        data = await asyncio.to_thread(_sync_fetch)
        if data.get("status") == "success":
            return {
                "status": "success",
                "public_ip": data.get("query"),
                "isp": data.get("isp"),
                "asn": data.get("as"),
                "city": data.get("city"),
                "country": data.get("country"),
                "lookup_time": datetime.now().strftime("%H:%M:%S"),
            }
        return {
            "status": "error",
            "message": data.get("message", "Nhà cung cấp tra cứu phản hồi lỗi"),
        }
    except Exception as e:
        logger.debug(f"Lỗi tra cứu ISP: {e}")
        return {
            "status": "error",
            "message": "Không thể kết nối tới máy chủ tra cứu định tuyến IP Internet.",
        }
