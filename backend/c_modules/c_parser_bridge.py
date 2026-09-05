import os
import ctypes
import struct
import platform
from pathlib import Path
import logging

logger = logging.getLogger("network_monitor.c_bridge")

BASE_DIR = Path(__file__).resolve().parent

# =========================================================================
# CTyps Definitions mapping exactly to C struct
# =========================================================================
class SecurityThreat(ctypes.Structure):
    _fields_ = [
        ("has_threat", ctypes.c_int),
        ("severity", ctypes.c_int),
        ("threat_type", ctypes.c_char * 32),
        ("description", ctypes.c_char * 128)
    ]

class ParsedPacket(ctypes.Structure):
    _fields_ = [
        ("protocol", ctypes.c_char * 16),
        ("src_ip", ctypes.c_char * 16),
        ("dst_ip", ctypes.c_char * 16),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("packet_len", ctypes.c_uint32),
        ("tcp_flags_str", ctypes.c_char * 16),
        ("info", ctypes.c_char * 256),
        ("threat", SecurityThreat)
    ]

# Try to load the C shared library
c_lib = None
lib_name = "packet_parser.dll" if platform.system() == "Windows" else "packet_parser.so"
lib_path = BASE_DIR / lib_name

if lib_path.exists():
    try:
        c_lib = ctypes.CDLL(str(lib_path))
        c_lib.parse_network_packet.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ParsedPacket)]
        c_lib.parse_network_packet.restype = ctypes.c_int
        logger.info(f"Đã nạp thành công module C phân tích gói tin: {lib_name}")
    except Exception as e:
        logger.warning(f"Lỗi khi nạp DLL {lib_name}: {e}. Sẽ dùng Python Fallback.")
        c_lib = None
else:
    logger.info(f"Không tìm thấy thư viện C ({lib_name}). Sẽ kích hoạt bộ giả lập C-Parser thuần Python.")

# =========================================================================
# PURE PYTHON FALLBACK (Tương đương 100% mã C)
# =========================================================================
def python_fallback_parse(raw_data: bytes) -> ParsedPacket:
    """Giả lập chính xác hàm C khi máy không có trình biên dịch."""
    pkt = ParsedPacket()
    pkt.packet_len = len(raw_data)
    pkt.threat.has_threat = 0
    pkt.protocol = b"UNKNOWN"
    
    if len(raw_data) < 14:
        return pkt

    # Phân tích Ethernet
    eth_header = raw_data[:14]
    eth_fields = struct.unpack("!6s6sH", eth_header)
    ethertype = eth_fields[2]
    offset = 14

    if ethertype == 0x0806:
        # ARP
        pkt.protocol = b"ARP"
        if len(raw_data) >= offset + 28:
            arp_fields = struct.unpack("!HHBBH6s4s6s4s", raw_data[offset:offset+28])
            opcode = arp_fields[4]
            sender_ip = ".".join(map(str, arp_fields[6]))
            target_ip = ".".join(map(str, arp_fields[8]))
            pkt.src_ip = sender_ip.encode()
            pkt.dst_ip = target_ip.encode()
            
            if opcode == 1:
                pkt.info = f"ARP Request: Who has {target_ip}? Tell {sender_ip}".encode()
            elif opcode == 2:
                sender_mac = ":".join(f"{b:02X}" for b in arp_fields[5])
                pkt.info = f"ARP Reply: {sender_ip} is at {sender_mac}".encode()
        return pkt

    if ethertype != 0x0800:
        return pkt # Not IPv4

    # Phân tích IPv4
    if len(raw_data) < offset + 20:
        return pkt

    ip_header = raw_data[offset:offset+20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    ip_header_len = ihl * 4
    total_length = iph[2]
    protocol = iph[6]
    
    src_ip = ".".join(map(str, iph[8]))
    dst_ip = ".".join(map(str, iph[9]))
    
    pkt.src_ip = src_ip.encode()
    pkt.dst_ip = dst_ip.encode()

    if total_length > len(raw_data) - offset:
        pkt.threat.has_threat = 1
        pkt.threat.severity = 2
        pkt.threat.threat_type = b"MALFORMED_IP"
        pkt.threat.description = b"Chieu dai goi IP vuot qua khung du lieu."

    offset += ip_header_len

    if protocol == 6:
        # TCP
        if len(raw_data) >= offset + 20:
            tcp_header = raw_data[offset:offset+20]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            pkt.protocol = b"TCP"
            pkt.src_port = tcph[0]
            pkt.dst_port = tcph[1]
            seq = tcph[2]
            flags = tcph[5]
            
            flag_str = ""
            if flags & 0x02: flag_str += "S"
            if flags & 0x10: flag_str += "A"
            if flags & 0x01: flag_str += "F"
            if flags & 0x04: flag_str += "R"
            if flags & 0x08: flag_str += "P"
            if flags & 0x20: flag_str += "U"
            if not flag_str: flag_str = "NONE"
            
            pkt.tcp_flags_str = flag_str.encode()
            pkt.info = f"TCP {flag_str}: {pkt.src_port} -> {pkt.dst_port} Seq={seq}".encode()

            # Security Heuristics (như module C)
            if flags == 0x00:
                pkt.threat.has_threat = 1
                pkt.threat.severity = 3
                pkt.threat.threat_type = b"TCP_NULL_SCAN"
                pkt.threat.description = b"Null Scan phat hien"
            elif flags == 0x29: # FIN PSH URG
                pkt.threat.has_threat = 1
                pkt.threat.severity = 3
                pkt.threat.threat_type = b"TCP_XMAS_SCAN"
                pkt.threat.description = b"XMAS Scan phat hien"

    elif protocol == 17:
        # UDP
        if len(raw_data) >= offset + 8:
            udp_header = raw_data[offset:offset+8]
            udph = struct.unpack("!HHHH", udp_header)
            pkt.protocol = b"UDP"
            pkt.src_port = udph[0]
            pkt.dst_port = udph[1]
            pkt.info = f"UDP: {pkt.src_port} -> {pkt.dst_port} Len={udph[2]}".encode()

    elif protocol == 1:
        # ICMP
        if len(raw_data) >= offset + 8:
            icmp_header = raw_data[offset:offset+8]
            icmph = struct.unpack("!BBHHH", icmp_header)
            pkt.protocol = b"ICMP"
            if icmph[0] == 8:
                pkt.info = f"ICMP Echo Request Seq={icmph[4]}".encode()
            elif icmph[0] == 0:
                pkt.info = f"ICMP Echo Reply Seq={icmph[4]}".encode()

    return pkt

def parse_packet(raw_data: bytes) -> dict:
    """Wrapper chính cho hệ thống."""
    if c_lib:
        pkt = ParsedPacket()
        c_lib.parse_network_packet(raw_data, len(raw_data), ctypes.byref(pkt))
    else:
        pkt = python_fallback_parse(raw_data)
        
    return {
        "protocol": pkt.protocol.decode('utf-8', 'ignore'),
        "src_ip": pkt.src_ip.decode('utf-8', 'ignore'),
        "dst_ip": pkt.dst_ip.decode('utf-8', 'ignore'),
        "src_port": pkt.src_port,
        "dst_port": pkt.dst_port,
        "packet_len": pkt.packet_len,
        "tcp_flags": pkt.tcp_flags_str.decode('utf-8', 'ignore'),
        "info": pkt.info.decode('utf-8', 'ignore'),
        "has_threat": pkt.threat.has_threat == 1,
        "threat_severity": pkt.threat.severity,
        "threat_type": pkt.threat.threat_type.decode('utf-8', 'ignore'),
        "threat_desc": pkt.threat.description.decode('utf-8', 'ignore')
    }

def test_parser():
    # Synthetic TCP SYN Packet for testing
    # Ethernet (14) + IP (20) + TCP (20)
    syn_packet = bytes.fromhex(
        "001122334455" "AABBCCDDEEFF" "0800" # Eth
        "45000028" "00004000" "4006A911" "C0A8010A" "C0A80101" # IPv4 (192.168.1.10 -> 192.168.1.1)
        "D4310050" "00000000" "00000000" "50022000" "00000000" # TCP SYN to Port 80
    )
    res = parse_packet(syn_packet)
    print("Test Parser Result:", res)
    assert res["protocol"] == "TCP"
    assert res["tcp_flags"] == "S"
    print("OK")
