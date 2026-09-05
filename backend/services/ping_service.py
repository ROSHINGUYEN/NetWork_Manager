"""
Service ping thiết bị và đọc bảng ARP của hệ điều hành.

Toàn bộ thao tác dùng lệnh hệ thống có sẵn (`ping`, `arp`/`ip neigh`) qua
asyncio subprocess (không cần quyền admin/root, không cần raw socket,
chạy được trên cả Windows lẫn Linux/macOS).
"""

from __future__ import annotations

import asyncio
import logging
import platform
import re
from typing import Optional

logger = logging.getLogger("network_monitor.ping")

IS_WINDOWS = platform.system().lower() == "windows"
_ping_missing_warned = False


def _build_ping_cmd(ip: str, count: int, timeout_ms: int) -> list[str]:
    if IS_WINDOWS:
        return ["ping", "-n", str(count), "-w", str(timeout_ms), ip]
    timeout_sec = max(1, round(timeout_ms / 1000))
    return ["ping", "-c", str(count), "-W", str(timeout_sec), ip]


def _parse_ping_output(ip: str, output: str) -> dict:
    """Trích xuất thời gian phản hồi (ms), tỉ lệ mất gói (%) và TTL từ output ping."""
    times = [float(x) for x in re.findall(r"time[=<]\s*([\d.]+)\s*ms", output, re.IGNORECASE)]
    loss_match = re.search(r"(\d+(?:\.\d+)?)\s*%\s*(?:packet\s*)?loss", output, re.IGNORECASE)
    ttl_match = re.search(r"\bttl[=:]\s*(\d+)", output, re.IGNORECASE)

    alive = len(times) > 0
    avg_latency = round(sum(times) / len(times), 2) if times else None
    if loss_match:
        packet_loss = float(loss_match.group(1))
    else:
        packet_loss = 0.0 if alive else 100.0

    ttl_val = int(ttl_match.group(1)) if ttl_match else None

    return {
        "ip": ip,
        "alive": alive,
        "latency_ms": avg_latency,
        "packet_loss": packet_loss,
        "ttl": ttl_val,
    }


async def ping_host(ip: str, count: int = 1, timeout_ms: int = 1000) -> dict:
    """
    Ping 1 địa chỉ IP bằng lệnh ping của hệ điều hành.

    Trả về: {"ip": str, "alive": bool, "latency_ms": float|None, "packet_loss": float}
    """
    cmd = _build_ping_cmd(ip, count, timeout_ms)
    overall_timeout = (timeout_ms / 1000.0) * count + 2.0

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        global _ping_missing_warned
        if not _ping_missing_warned:
            logger.error(
                "Không tìm thấy lệnh 'ping' trên hệ thống này. "
                "Cài đặt tiện ích ping của hệ điều hành để tính năng quét mạng hoạt động "
                "(thông báo này chỉ hiển thị 1 lần)."
            )
            _ping_missing_warned = True
        return {"ip": ip, "alive": False, "latency_ms": None, "packet_loss": 100.0}
    except Exception as e:
        logger.debug(f"Không khởi chạy được tiến trình ping tới {ip}: {e}")
        return {"ip": ip, "alive": False, "latency_ms": None, "packet_loss": 100.0}

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=overall_timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return {"ip": ip, "alive": False, "latency_ms": None, "packet_loss": 100.0}

    output = stdout.decode(errors="ignore")
    return _parse_ping_output(ip, output)


def _parse_arp_output(output: str) -> dict[str, str]:
    """Phân tích output của 'arp -a' (Windows/Unix) hoặc 'ip neigh' (Linux)."""
    result: dict[str, str] = {}
    pattern = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3}).*?"
        r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
    )
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            ip, mac = match.group(1), match.group(2)
            result[ip] = mac.upper().replace("-", ":")
    return result


async def get_arp_table() -> dict[str, str]:
    """Đọc bảng ARP hiện tại của hệ điều hành, trả về dict {ip: mac}."""
    commands: list[list[str]]
    if IS_WINDOWS:
        commands = [["arp", "-a"]]
    else:
        commands = [["ip", "neigh"], ["arp", "-n"], ["arp", "-a"]]

    for cmd in commands:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = stdout.decode(errors="ignore")
            table = _parse_arp_output(output)
            if table:
                return table
        except FileNotFoundError:
            continue
        except Exception as e:
            logger.debug(f"Lệnh '{' '.join(cmd)}' đọc ARP thất bại: {e}")
            continue

    logger.warning("Không đọc được bảng ARP bằng bất kỳ lệnh hệ thống nào.")
    return {}


async def resolve_hostname(ip: str, timeout: float = 1.5) -> str:
    """Phân giải ngược DNS/NetBIOS để lấy hostname của 1 IP, timeout ngắn để không chặn quét."""
    import socket

    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=timeout
        )
        return result[0]
    except Exception:
        return ""
