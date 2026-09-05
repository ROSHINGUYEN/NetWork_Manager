import logging
import time
from datetime import datetime, timezone
from backend.memory_store import SecurityEventStore, DeviceStore

logger = logging.getLogger("network_monitor.security")

class SecurityEngine:
    """
    Động cơ phát hiện bất thường an ninh mạng.
    Thực hiện đánh giá các dấu hiệu theo giáo trình Cybersecurity.
    """
    def __init__(self, sec_repo: SecurityEventStore, dev_repo: DeviceStore):
        self.sec_repo = sec_repo
        self.dev_repo = dev_repo
        self.known_macs = set()
        self.ip_mac_map = {}
        
        # Ports cảnh báo (ví dụ: Telnet, SMB, RDP, MSSQL, VNC)
        self.dangerous_ports = {23, 445, 3389, 1433, 5900}
        
    async def initialize(self):
        """Khởi tạo từ database hiện tại"""
        devices = await self.dev_repo.get_all()
        for d in devices:
            self.known_macs.add(d["mac"])
            self.ip_mac_map[d["ip"]] = d["mac"]
            
    async def analyze_device_discovery(self, ip: str, mac: str, is_new: bool, open_ports: list[int] = None):
        """Phân tích thiết bị vừa phát hiện"""
        now_str = datetime.utcnow().isoformat()
        alerts = []
        
        # 1. Phát hiện thiết bị mới
        if is_new and mac not in self.known_macs:
            alerts.append({
                "severity": 1,
                "threat_category": "NEW_DEVICE",
                "details": f"Thiết bị mới xuất hiện trên mạng LAN: {mac} ({ip})"
            })
            self.known_macs.add(mac)
            self.ip_mac_map[ip] = mac
            
        # 2. Phát hiện ARP Spoofing / IP Conflict
        if ip in self.ip_mac_map and self.ip_mac_map[ip] != mac:
            alerts.append({
                "severity": 3,
                "threat_category": "ARP_SPOOFING",
                "details": f"Xung đột IP hoặc nghi ngờ ARP Spoofing: {ip} đang bị tranh chấp bởi {self.ip_mac_map[ip]} và {mac}."
            })
            self.ip_mac_map[ip] = mac
            
        # 3. Phát hiện Dangerous Ports
        if open_ports:
            suspicious = [p for p in open_ports if p in self.dangerous_ports]
            if suspicious:
                alerts.append({
                    "severity": 2,
                    "threat_category": "SUSPICIOUS_PORT",
                    "details": f"Thiết bị mở các cổng nguy hiểm: {suspicious} (ví dụ: 23=Telnet, 445=SMB, 3389=RDP)."
                })
                
        # Lưu và trả về cảnh báo
        saved_alerts = []
        for a in alerts:
            res = await self.sec_repo.add(
                severity=a["severity"],
                threat_category=a["threat_category"],
                src_ip=ip,
                dst_ip=None,
                details=a["details"],
                created_at=now_str
            )
            saved_alerts.append(res)
            if a["severity"] >= 2:
                logger.warning(f"SECURITY ALERT [{a['threat_category']}]: {a['details']}")
            else:
                logger.info(f"SECURITY INFO [{a['threat_category']}]: {a['details']}")
                
        return saved_alerts

    async def log_threat_from_packet(self, threat: dict):
        """Ghi nhận cảnh báo từ Packet Parser (C-Module)"""
        now_str = datetime.utcnow().isoformat()
        res = await self.sec_repo.add(
            severity=threat.get("threat_severity", 2),
            threat_category=threat.get("threat_type", "PACKET_ANOMALY"),
            src_ip=threat.get("src_ip"),
            dst_ip=threat.get("dst_ip"),
            details=threat.get("threat_desc", "Bất thường gói tin được phát hiện."),
            created_at=now_str
        )
        return res
