"""
Service thu thập thông tin chi tiết về Network Adapter (Wi-Fi hoặc Ethernet).
Hỗ trợ cả Windows (netsh wlan / psutil) và Linux (nmcli / iwconfig / sysfs / psutil).
"""

from __future__ import annotations

import logging
import platform
import re
import subprocess
from typing import Optional

import psutil

logger = logging.getLogger("network_monitor.interface_info")
IS_WINDOWS = platform.system().lower() == "windows"


def get_wifi_details_windows() -> Optional[dict]:
    """Lấy thông số Wi-Fi chi tiết trên Windows bằng lệnh netsh wlan show interfaces."""
    try:
        cmd = ["netsh", "wlan", "show", "interfaces"]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        output = subprocess.check_output(cmd, creationflags=flags, timeout=3).decode(errors="ignore")

        if "There is no wireless interface" in output or "State" not in output:
            return None

        data = {
            "type": "wifi",
            "interface_type": "Wi-Fi",
            "adapter": "Wi-Fi",
            "adapter_name": "Wi-Fi",
            "ssid": None,
            "bssid": None,
            "signal_percent": None,
            "signal_quality": None,
            "radio_type": None,
            "link_speed_rx": None,
            "link_speed_tx": None,
            "rx_rate_mbps": None,
            "tx_rate_mbps": None,
            "channel": None,
            "state": "disconnected",
        }

        for line in output.splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            key, val = [x.strip() for x in line.split(":", 1)]
            k_lower = key.lower()

            if k_lower == "name":
                data["adapter"] = val
                data["adapter_name"] = val
            elif k_lower == "state":
                data["state"] = val
            elif k_lower == "ssid":
                data["ssid"] = val
            elif k_lower == "bssid":
                data["bssid"] = val.upper().replace("-", ":")
            elif k_lower == "signal":
                sig_match = re.search(r"(\d+)", val)
                if sig_match:
                    sig_val = int(sig_match.group(1))
                    data["signal_percent"] = sig_val
                    data["signal_quality"] = sig_val
            elif "radio type" in k_lower:
                data["radio_type"] = val
            elif "channel" in k_lower:
                data["channel"] = val
            elif "receive rate" in k_lower:
                data["link_speed_rx"] = val
                m = re.search(r"([\d\.]+)", val)
                if m:
                    data["rx_rate_mbps"] = float(m.group(1))
            elif "transmit rate" in k_lower:
                data["link_speed_tx"] = val
                m = re.search(r"([\d\.]+)", val)
                if m:
                    data["tx_rate_mbps"] = float(m.group(1))

        if data.get("state") == "connected" and data.get("ssid"):
            return data
        return None
    except Exception as e:
        logger.debug(f"Không lấy được thông tin Wi-Fi Windows: {e}")
        return None


def get_wifi_details_linux() -> Optional[dict]:
    """Lấy thông số Wi-Fi chi tiết trên Linux bằng nmcli hoặc iwconfig."""
    try:
        cmd = ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"]
        output = subprocess.check_output(cmd, timeout=3).decode(errors="ignore")
        for line in output.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 4 and parts[1] == "wifi" and parts[2] == "connected":
                dev, ssid = parts[0], parts[3]
                sig_val = None
                try:
                    wout = subprocess.check_output(["nmcli", "-t", "-f", "IN-USE,SIGNAL,SSID,BSSID", "dev", "wifi"], timeout=3).decode(errors="ignore")
                    for wline in wout.splitlines():
                        if wline.startswith("*"):
                            wparts = wline.split(":")
                            if len(wparts) >= 3:
                                sig_val = int(wparts[1])
                                bssid = wparts[3] if len(wparts) >= 4 else None
                                return {
                                    "type": "wifi",
                                    "adapter": dev,
                                    "ssid": ssid,
                                    "bssid": bssid,
                                    "signal_percent": sig_val,
                                    "radio_type": "802.11",
                                    "state": "connected",
                                }
                except Exception:
                    pass
                return {
                    "type": "wifi",
                    "adapter": dev,
                    "ssid": ssid,
                    "bssid": None,
                    "signal_percent": sig_val,
                    "state": "connected",
                }
    except Exception:
        pass
    return None


def get_ethernet_details(active_iface: Optional[str]) -> dict:
    """Lấy thông số kết nối mạng có dây Ethernet."""
    stats = psutil.net_if_stats()
    chosen_name = active_iface or "Ethernet"
    chosen_stat = stats.get(chosen_name)

    if not chosen_stat:
        for name, stat in stats.items():
            if stat.isup and "loopback" not in name.lower() and "wi-fi" not in name.lower() and "wlan" not in name.lower():
                chosen_name = name
                chosen_stat = stat
                break

    speed_str = "1000 Mbps (Gigabit)"
    duplex_str = "Full Duplex"
    mtu = 1500
    is_up = True

    if chosen_stat:
        is_up = chosen_stat.isup
        mtu = chosen_stat.mtu
        if chosen_stat.speed > 0:
            speed_str = f"{chosen_stat.speed} Mbps"
            if chosen_stat.speed >= 1000:
                speed_str += " (Gigabit)"
        duplex_str = "Full Duplex" if chosen_stat.duplex == 2 else "Half Duplex" if chosen_stat.duplex == 1 else "Auto"

    speed_mbps = chosen_stat.speed if (chosen_stat and chosen_stat.speed > 0) else 1000

    return {
        "type": "ethernet",
        "interface_type": "Ethernet",
        "adapter": chosen_name,
        "adapter_name": chosen_name,
        "speed": speed_str,
        "speed_mbps": speed_mbps,
        "duplex": duplex_str,
        "mtu": mtu,
        "state": "connected" if is_up else "disconnected",
    }


def get_active_adapter_info(active_iface: Optional[str] = None) -> dict:
    """
    Trả về thông số tổng hợp của adapter đang kết nối:
    Ưu tiên Wi-Fi nếu đang kết nối Wi-Fi, ngược lại trả về Ethernet.
    """
    wifi_data = get_wifi_details_windows() if IS_WINDOWS else get_wifi_details_linux()
    if wifi_data and wifi_data.get("state") == "connected":
        return wifi_data

    return get_ethernet_details(active_iface)
