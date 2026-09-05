"""
Service tra cứu tên hãng sản xuất (vendor) của thiết bị dựa trên 3 byte
đầu của địa chỉ MAC (mã OUI - Organizationally Unique Identifier).

Ứng dụng đi kèm một CSDL OUI tối giản, chỉ bao gồm một số hãng phổ biến,
để không phụ thuộc Internet lúc chạy. Nếu cần độ chính xác/độ phủ cao hơn,
tải file "oui.txt" chính thức từ IEEE:
    https://standards-oui.ieee.org/oui/oui.txt
và đặt vào: backend/data/oui.txt
(mỗi dòng dạng "AABBCC   Tên hãng"), hệ thống sẽ tự nạp thêm lúc khởi động
mà KHÔNG cần gọi mạng trong lúc chạy chương trình.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("network_monitor.vendor")

# CSDL OUI tích hợp sẵn (tối giản) - key là 6 ký tự hex viết hoa không dấu phân cách.
_BUILTIN_OUI: dict[str, str] = {
    # -- Thiết bị nhúng / máy ảo hoá / DIY thường gặp trong LAN gia đình --
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading Ltd",
    "E45F01": "Raspberry Pi Trading Ltd",
    "D83ADD": "Raspberry Pi Trading Ltd",
    "005056": "VMware, Inc.",
    "000C29": "VMware, Inc.",
    "001C14": "VMware, Inc.",
    "080027": "Oracle VirtualBox",
    "00155D": "Microsoft (Hyper-V Virtual Adapter)",
    "240AC4": "Espressif Inc. (ESP8266/ESP32)",
    "30AEA4": "Espressif Inc. (ESP8266/ESP32)",
    "ACD074": "Espressif Inc. (ESP8266/ESP32)",
    "ECFABC": "Espressif Inc. (ESP8266/ESP32)",
    "B4E62D": "Espressif Inc. (ESP8266/ESP32)",
    "5CCF7F": "Espressif Inc. (ESP8266/ESP32)",
    "18FE34": "Espressif Inc. (ESP8266/ESP32)",
    # -- Máy tính / hãng phần cứng lớn --
    "3C15C2": "Apple, Inc.",
    "A45E60": "Apple, Inc.",
    "F01898": "Apple, Inc.",
    "001B63": "Apple, Inc.",
    "F4F5D8": "Google, Inc.",
    "001A11": "Google, Inc.",
    "3C5AB4": "Google, Inc.",
    "44650D": "Amazon Technologies Inc.",
    "74C246": "Amazon Technologies Inc.",
    "F8B7E2": "Amazon Technologies Inc.",
    "001517": "Intel Corporate",
    "3C970E": "Intel Corporate",
    "A4C3F0": "Intel Corporate",
    "B8CA3A": "Dell Inc.",
    "D4BED9": "Dell Inc.",
    "9C8E99": "Hewlett Packard",
    "3CD92B": "Hewlett Packard",
    "1C872C": "ASUSTek COMPUTER INC.",
    "50465D": "ASUSTek COMPUTER INC.",
    "001CBE": "Nintendo Co., Ltd.",
    "001BEA": "Nintendo Co., Ltd.",
    # -- Thiết bị mạng (router/switch/AP) --
    "7CD1C3": "TP-Link Technologies Co., Ltd.",
    "50C7BF": "TP-Link Technologies Co., Ltd.",
    "98DAC4": "TP-Link Technologies Co., Ltd.",
    "A06391": "NETGEAR, Inc.",
    "34C93D": "NETGEAR, Inc.",
    "001A7D": "D-Link Corporation",
    "0026F2": "D-Link Corporation",
    "3497F6": "Ubiquiti Networks, Inc.",
    "24A43C": "Ubiquiti Networks, Inc.",
    "F09FC2": "Ubiquiti Networks, Inc.",
    # -- Điện thoại / thiết bị di động / Smart TV --
    "8C71F8": "Samsung Electronics Co., Ltd.",
    "E8508B": "Samsung Electronics Co., Ltd.",
    "5C0A5B": "Samsung Electronics Co., Ltd.",
    "D0D003": "Samsung Electronics Co., Ltd.",
    "B407C9": "Samsung Electronics Co., Ltd.",
    "64DB43": "Motorola / Lenovo Mobility",
    "002436": "Lenovo Mobile",
    "B8B81E": "Xiaomi Communications",
    "7802F8": "Xiaomi Communications",
    "444F5C": "Xiaomi Communications",
    "E470B8": "Xiaomi Communications",
    "60A44C": "Apple, Inc.",
    "BC926B": "Apple, Inc.",
    "A887ED": "Apple, Inc.",
    "DC2B61": "Apple, Inc.",
    "784F43": "Apple, Inc.",
    "E4C32A": "Apple, Inc.",
    "48D705": "Apple, Inc.",
    "F434F0": "Apple, Inc.",
    "38F9D3": "Apple, Inc.",
    "68D93C": "Apple, Inc.",
    "B0AC82": "China Dragon Technology (Smart Home/IoT)",
    "D896E0": "Tuya Smart Inc. (IoT)",
    # -- Modem / Router / Nhà mạng VN (ZTE, Huawei, Viettel, VNPT) --
    "A0092E": "ZTE Corporation",
    "30EBAE": "ZTE Corporation",
    "709F2D": "ZTE Corporation",
    "C864C7": "ZTE Corporation",
    "F4E3FB": "Huawei Technologies Co., Ltd.",
    "00E0FC": "Huawei Technologies Co., Ltd.",
    "404D8E": "Huawei Technologies Co., Ltd.",
    "D46AA8": "Huawei Technologies Co., Ltd.",
    "7079B3": "Huawei Technologies Co., Ltd.",
    "AC84C6": "TP-Link Corporation",
    "B09575": "TP-Link Corporation",
    "003192": "DrayTek Corp.",
    "001E58": "D-Link Corporation",
    "0840F3": "Cisco Systems, Inc.",
    "00000C": "Cisco Systems, Inc.",
    "18A6F7": "Shenzhen Tenda Technology",
    # -- Camera an ninh / NVR (Hikvision, Ezviz, Dahua, Imou) --
    "E0BAAD": "Hangzhou Hikvision Digital Tech (Ezviz/Hikvision)",
    "B09928": "Hangzhou Hikvision Digital Tech (Ezviz/Hikvision)",
    "C42F90": "Hangzhou Hikvision Digital Tech (Ezviz/Hikvision)",
    "4419B6": "Hangzhou Hikvision Digital Tech (Ezviz/Hikvision)",
    "A41437": "Zhejiang Dahua Technology (Dahua/Imou)",
    "3C18A0": "Zhejiang Dahua Technology (Dahua/Imou)",
    "48EA63": "Zhejiang Dahua Technology (Dahua/Imou)",
    # -- Card mạng PC & Chipset phổ biến --
    "22376C": "Realtek Semiconductor Corp.",
    "00E04C": "Realtek Semiconductor Corp.",
    "2C56DC": "Realtek Semiconductor Corp.",
    "4851B7": "Intel Corporate",
    "80C5F2": "Intel Corporate",
    "001F16": "Wistron InfoComm (Acer/Dell OEM)",
    "40B034": "Sony Interactive Entertainment (PlayStation)",
    "F8461C": "Sony Corporation (Bravia TV)",
    "000420": "LG Electronics (Smart TV/WebOS)",
    "70288B": "LG Electronics",
}

_extra_oui: dict[str, str] = {}
_extra_loaded = False


def _load_extra_oui_file() -> None:
    """Nạp thêm CSDL OUI mở rộng từ backend/data/oui.txt nếu có (chỉ 1 lần)."""
    global _extra_loaded
    if _extra_loaded:
        return
    _extra_loaded = True

    oui_path = Path(__file__).resolve().parent.parent / "data" / "oui.txt"
    if not oui_path.exists():
        return

    try:
        loaded_count = 0
        with open(oui_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                prefix = parts[0].upper().replace("-", "").replace(":", "")
                if len(prefix) >= 6:
                    _extra_oui[prefix[:6]] = parts[1].strip()
                    loaded_count += 1
        logger.info(f"Đã nạp {loaded_count} bản ghi OUI mở rộng từ {oui_path}")
    except Exception as e:
        logger.warning(f"Không thể nạp file OUI mở rộng '{oui_path}': {e}")


def lookup_vendor(mac: str) -> str:
    """Tra cứu tên hãng sản xuất từ địa chỉ MAC. Trả về 'Unknown Vendor' nếu không rõ."""
    if not mac:
        return "Unknown Vendor"

    _load_extra_oui_file()

    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    if prefix in _extra_oui:
        return _extra_oui[prefix]
    if prefix in _BUILTIN_OUI:
        return _BUILTIN_OUI[prefix]
    return "Unknown Vendor"
