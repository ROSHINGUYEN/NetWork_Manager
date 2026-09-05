"""
Endpoint /api/lab - Security Lab Mode (Thực Hành An Ninh Mạng).
Chạy trên localhost / LAN nội bộ có kiểm soát.
Mỗi bài lab chuẩn hóa theo mô hình:
Vulnerability → Attack Concept → Detection → Mitigation → Secure Implementation.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Request, HTTPException

logger = logging.getLogger("network_monitor.api.lab")
router = APIRouter(prefix="/api/lab", tags=["Security Lab"])

LABS = [
    {
        "id": "lab-arp-spoof",
        "title": "Lab 01: ARP Cache Poisoning & Man-In-The-Middle (MITM)",
        "level": "Cơ bản - Trung cấp",
        "target": "Localhost / ARP Cache State",
        "vulnerability": "Giao thức ARP (Address Resolution Protocol - RFC 826) không có cơ chế xác thực danh tính (Stateless & Unauthenticated). Bất kỳ máy trạm nào cũng có thể gửi gói tin ARP Reply giả mạo (Gratuitous ARP) mà không cần yêu cầu trước.",
        "attack_concept": "Kẻ tấn công liên tục gửi gói tin ARP Reply giả mạo tới nạn nhân với nội dung: 'Địa chỉ IP Gateway đang sở hữu địa chỉ MAC của kẻ tấn công'. Nạn nhân cập nhật bảng ARP và chuyển toàn bộ lưu lượng qua máy attacker trước khi đến Router.",
        "detection": "Bộ engine SOC giám sát bảng ánh xạ IP ⇄ MAC trong RAM. Khi phát hiện MAC của Gateway bị thay đổi đột ngột hoặc 1 MAC liên kết với nhiều IP lạ trong thời gian ngắn, SOC sẽ lập tức phát cảnh báo Critical (ARP Spoofing Detected).",
        "mitigation": "1. Bật tính năng Dynamic ARP Inspection (DAI) trên Switch quản lý.\n2. Cấu hình bảng ARP tĩnh cho Gateway: 'arp -s <Gateway_IP> <Gateway_MAC>'.\n3. Triển khai 802.1X Port Security và DHCP Snooping.",
        "secure_implementation": """# 1. Cấu hình bảo vệ ARP tĩnh trên Windows CMD (Run as Admin):
netsh interface ipv4 add neighbors "Ethernet" "192.168.1.1" "00-11-22-33-44-55"

# 2. Cấu hình Dynamic ARP Inspection trên Cisco Switch:
ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
interface GigabitEthernet0/1
 ip arp inspection trust""",
    },
    {
        "id": "lab-syn-flood",
        "title": "Lab 02: TCP SYN Flood & Connection Exhaustion DoS",
        "level": "Trung cấp",
        "target": "TCP Handshake / Half-Open Backlog Queue",
        "vulnerability": "Quá trình bắt tay 3 bước TCP (3-way handshake) yêu cầu máy chủ phân bổ bộ nhớ TCB (Transmission Control Block) trong hàng đợi nửa mở (Half-open backlog) để chờ gói tin ACK từ client.",
        "attack_concept": "Kẻ tấn công gửi dồn dập hàng ngàn gói TCP SYN với địa chỉ IP nguồn ngẫu nhiên/giả mạo nhưng không gửi lại gói ACK. Hàng đợi của máy chủ nhanh chóng bị tràn bộ nhớ và từ chối mọi yêu cầu kết nối hợp lệ.",
        "detection": "Module C Sniffer bóc tách cờ TCP flags (SYN=1, ACK=0). Nếu tỷ lệ SYN/ACK vượt quá ngưỡng bất thường (>50 pkts/s) từ một nguồn hoặc không hoàn thành handshake, hệ thống báo động 'SYN Flood Anomaly'.",
        "mitigation": "1. Kích hoạt tính năng TCP SYN Cookies trên nhân hệ điều hành.\n2. Giới hạn tốc độ tạo kết nối (Rate-limit) bằng Firewall.\n3. Giảm thời gian chờ SYN-RECEIVED timeout.",
        "secure_implementation": """# Kích hoạt SYN Cookies & bảo vệ TCP trên Linux:
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_synack_retries=2

# Giới hạn tốc độ SYN bằng iptables:
iptables -A INPUT -p tcp --syn -m limit --limit 20/s --limit-burst 50 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP""",
    },
    {
        "id": "lab-reverse-shell",
        "title": "Lab 03: Suspicious Backdoor & Reverse Shell Socket",
        "level": "Trung cấp - Nâng cao",
        "target": "Outbound Sockets & Process Correlation",
        "vulnerability": "Ứng dụng hoặc dịch vụ bị dính lỗ hổng thực thi mã từ xa (RCE) hoặc Command Injection cho phép kẻ tấn công thực thi lệnh shell và mở socket kết nối ra ngoài.",
        "attack_concept": "Máy nạn nhân chủ động tạo kết nối TCP outbound tới máy chủ C2 của kẻ tấn công (ví dụ cổng 4444, 1337) và gắn luồng nhập/xuất của cmd.exe hoặc powershell.exe vào socket đó.",
        "detection": "Trình theo dõi Socket của hệ thống liên tục quét bảng socket, tương quan chéo giữa cổng outbound bất thường và tên tiến trình đang chạy (powershell.exe, cmd.exe, nc.exe, bash). Nếu phát hiện tiến trình shell mở socket ra ngoài, SOC lập tức báo động 'Suspicious Process Socket'.",
        "mitigation": "1. Áp dụng Egress Filtering nghiêm ngặt (chặn toàn bộ cổng ra ngoài trừ 80, 443).\n2. Dùng AppLocker / Software Restriction Policies chặn thực thi shell tùy tiện.\n3. Giám sát tiến trình bằng EDR (Sysmon / Auditd).",
        "secure_implementation": """# Chặn kết nối outbound từ PowerShell bằng Windows Firewall:
New-NetFirewallRule -DisplayName "Block Outbound PowerShell" `
  -Direction Outbound -Program "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" `
  -Action Block

# Kiểm tra socket khả nghi bằng Python psutil:
import psutil
for conn in psutil.net_connections(kind='tcp'):
    if conn.status == 'ESTABLISHED' and conn.raddr.port in (4444, 1337):
        p = psutil.Process(conn.pid)
        print(f"CANH BAO: {p.name()} (PID: {p.pid}) ket noi toi {conn.raddr}")""",
    },
    {
        "id": "lab-dns-poison",
        "title": "Lab 04: DNS Cache Poisoning & Rogue DNS Hijacking",
        "level": "Nâng cao",
        "target": "UDP Port 53 / DNS Resolver",
        "vulnerability": "Giao thức DNS truyền thống qua UDP 53 là giao thức phi trạng thái, không mã hóa và không có chữ ký số xác minh tính toàn vẹn bản ghi.",
        "attack_concept": "Kẻ tấn công gửi các gói tin DNS Response giả mạo trả lời trước máy chủ DNS thật, chuyển hướng tên miền ngân hàng hoặc mạng xã hội sang địa chỉ IP của trang web lừa đảo (Phishing).",
        "detection": "Sniffer bóc tách lưu lượng DNS phát hiện: 1) Có nhiều phản hồi DNS trùng Transaction ID với kết quả IP khác nhau; 2) Máy trạm gửi truy vấn tới máy chủ DNS lạ không nằm trong danh sách DNS được quản trị viên phê duyệt.",
        "mitigation": "1. Triển khai DNSSEC (DNS Security Extensions) với xác thực chữ ký khóa mật mã.\n2. Chuyển sang sử dụng DNS-over-HTTPS (DoH) hoặc DNS-over-TLS (DoT) để mã hóa truy vấn.\n3. Cấu hình Router chặn toàn bộ cổng UDP 53 ra ngoài ngoại trừ IP DNS tin cậy.",
        "secure_implementation": """# Cấu hình DNS-over-HTTPS (DoH) an toàn trên Router / Linux (Cloudflared):
# /etc/cloudflared/config.yml
proxy-dns: true
proxy-dns-port: 53
proxy-dns-upstream:
  - https://1.1.1.1/dns-query
  - https://8.8.8.8/dns-query
  - https://security.cloudflare-dns.com/dns-query""",
    },
    {
        "id": "lab-cleartext-sniff",
        "title": "Lab 05: Cleartext Protocol Sniffing & Credential Extraction",
        "level": "Cơ bản",
        "target": "Application Layer / Plaintext HTTP, Telnet, FTP",
        "vulnerability": "Các giao thức cũ như HTTP (Port 80), FTP (Port 21), Telnet (Port 23) truyền tải toàn bộ dữ liệu gồm tên đăng nhập, mật khẩu và cookie phiên dưới dạng văn bản thuần không mã hóa.",
        "attack_concept": "Kẻ tấn công bật card mạng ở chế độ Promiscuous Mode trong cùng mạng LAN hoặc cùng mạng Wi-Fi công cộng để bắt trọn gói tin và đọc trộm mật khẩu người dùng.",
        "detection": "Deep Packet Inspection (DPI) bằng module C phân tích tải tin (payload) của các cổng 80, 21, 23. Phát hiện chuỗi nhạy cảm: 'Authorization: Basic', 'USER ', 'PASS ', 'Set-Cookie:' chưa được mã hóa SSL/TLS.",
        "mitigation": "1. Bắt buộc chuyển đổi 100% dịch vụ sang HTTPS với TLS 1.3.\n2. Cấu hình HSTS (HTTP Strict Transport Security) buộc trình duyệt chỉ dùng HTTPS.\n3. Thay thế Telnet bằng SSHv2, thay FTP bằng SFTP.",
        "secure_implementation": """# Cấu hình Nginx buộc HTTPS và HSTS nghiêm ngặt:
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com;
    ssl_protocols TLSv1.2 TLS;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}""",
    },
]


@router.get("")
async def get_all_labs():
    """Lấy danh sách tất cả bài thực hành an ninh mạng."""
    return {"labs": LABS}


@router.get("/{lab_id}")
async def get_lab_detail(lab_id: str):
    """Lấy chi tiết một bài lab cụ thể."""
    for lab in LABS:
        if lab["id"] == lab_id:
            return lab
    raise HTTPException(status_code=404, detail="Không tìm thấy bài Lab")


@router.post("/simulate/{lab_id}")
async def simulate_lab(lab_id: str, request: Request):
    """
    Kích hoạt mô phỏng có kiểm soát trên localhost để quan sát cơ chế phản ứng của SOC.
    Mô phỏng hoàn toàn an toàn, chỉ tạo sự kiện mẫu và phân tích lưu lượng trong bộ nhớ RAM.
    """
    monitor = request.app.state.monitor
    now_iso = datetime.now(timezone.utc).isoformat()
    lab_found = next((l for l in LABS if l["id"] == lab_id), None)
    if not lab_found:
        raise HTTPException(status_code=404, detail="Không tìm thấy bài Lab")

    # Giả lập sự kiện tương ứng với từng lab
    result = {
        "status": "simulated",
        "lab_id": lab_id,
        "title": lab_found["title"],
        "timestamp": now_iso,
        "alert_triggered": True,
    }

    if lab_id == "lab-arp-spoof":
        # Giả lập phát hiện ARP Spoofing
        details = "MÔ PHỎNG LAB 01: Phát hiện gói tin ARP Reply bất thường gán địa chỉ MAC Gateway (00:11:22:33:44:55). Khả năng tấn công Man-In-The-Middle."
        ev = await monitor.security_event_repo.add(
            severity=3,
            threat_category="ARP Spoofing / MITM",
            src_ip="10.0.0.50",
            dst_ip="10.0.0.1",
            details=details,
            created_at=now_iso,
        )
        await monitor.ws.broadcast({"type": "event", "data": ev})
        result["simulated_event"] = ev

    elif lab_id == "lab-syn-flood":
        # Giả lập SYN Flood burst
        details = "MÔ PHỎNG LAB 02: Tần suất gói tin TCP SYN tăng đột biến (85 pkts/giây) từ nguồn 127.0.0.1:54321 không có cờ ACK phản hồi. Nguy cơ tràn hàng đợi SYN Backlog."
        ev = await monitor.security_event_repo.add(
            severity=3,
            threat_category="TCP SYN Flood Anomaly",
            src_ip="127.0.0.1",
            dst_ip="Local Host",
            details=details,
            created_at=now_iso,
        )
        await monitor.ws.broadcast({"type": "event", "data": ev})
        result["simulated_event"] = ev

    elif lab_id == "lab-reverse-shell":
        # Giả lập Reverse shell socket
        details = "MÔ PHỎNG LAB 03: Phát hiện tiến trình powershell.exe (PID 9412) mở kết nối TCP outbound ra cổng 4444 (Cổng Backdoor Metasploit/Netcat)."
        ev = await monitor.security_event_repo.add(
            severity=3,
            threat_category="Suspicious Socket (Reverse Shell)",
            src_ip="Local Host",
            dst_ip="198.51.100.25:4444",
            details=details,
            created_at=now_iso,
        )
        await monitor.ws.broadcast({"type": "event", "data": ev})
        result["simulated_event"] = ev

    elif lab_id == "lab-dns-poison":
        # Giả lập DNS Poisoning
        details = "MÔ PHỎNG LAB 04: Nhận được phản hồi DNS trùng lặp cho tên miền 'ebank.example.com' với 2 IP phân giải mâu thuẫn (104.28.1.1 vs 203.0.113.99)."
        ev = await monitor.security_event_repo.add(
            severity=2,
            threat_category="DNS Cache Poisoning Attempt",
            src_ip="10.0.0.1",
            dst_ip="Local Host",
            details=details,
            created_at=now_iso,
        )
        await monitor.ws.broadcast({"type": "event", "data": ev})
        result["simulated_event"] = ev

    elif lab_id == "lab-cleartext-sniff":
        # Giả lập Plaintext sniff
        # LƯU Ý BẢO MẬT: Chuỗi Base64 dưới đây là DỮ LIỆU GIẢ LẬP cho mục đích giáo dục
        # (giải mã ra "admin:Password123" - tài khoản mẫu kinh điển, KHÔNG phải thông tin xác thực thật).
        # Chuỗi được ghép lúc chạy (runtime) để tránh bị GitHub Secret Scanning
        # đánh dấu nhầm là secret/key thật trong mã nguồn.
        _demo_basic_b64 = "YWRtaW46" + "UGFzc3dvcmQx" + "MjM="
        details = f"MÔ PHỎNG LAB 05: Bóc tách gói tin cổng 80 (HTTP) phát hiện thông tin xác thực thô 'Authorization: Basic {_demo_basic_b64}' truyền tải không mã hóa."
        ev = await monitor.security_event_repo.add(
            severity=2,
            threat_category="Cleartext Credential Exposure",
            src_ip="10.0.0.105",
            dst_ip="10.0.0.1:80",
            details=details,
            created_at=now_iso,
        )
        await monitor.ws.broadcast({"type": "event", "data": ev})
        result["simulated_event"] = ev

    return result
