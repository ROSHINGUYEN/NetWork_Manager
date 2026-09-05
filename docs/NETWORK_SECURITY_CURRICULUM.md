# GIÁO TRÌNH ĐÀO TẠO AN NINH MẠNG & GIÁM SÁT SOC
**Khung Đào Tạo Kỹ Sư Giám Sát An Toàn Thông Tin (Security Operations Center - SOC Tier 1/2)**  
*Mã hệ thống: NSM| Nền tảng: Python + C Low-level + FastAPI + In-Memory RAM + WebSocket*

---

## 📌 GIỚI THIỆU & MỤC TIÊU KHÓA HỌC
Hệ thống **Network Security Monitor** được thiết kế như một phòng thí nghiệm thu nhỏ (Cyber Range Sandbox), cung cấp khả năng trực quan hóa các luồng dữ liệu mạng, bóc tách cấu trúc gói tin tầng thấp (L2 - L4) và mô phỏng các mối đe dọa an ninh mạng thường gặp trên hệ thống mạng nội bộ (LAN).

Khác biệt với các công cụ ghi log truyền thống,áp dụng kiến trúc **Zero-Footprint In-Memory RAM**, toàn bộ trạng thái mạng, các phiên bắt gói và sự kiện an ninh chỉ tồn tại trên RAM trong phiên làm việc, tự động giải phóng sạch khi ứng dụng kết thúc.

---

## 📐 KIẾN TRÚC HỆ THỐNG
1. **Lớp Thu Thập & Bóc Tách Cấp Thấp (C Low-Level Module)**:
   - Sử dụng ngôn ngữ C thuần túy để giải mã trực tiếp các struct nhị phân của Ethernet Header (`struct eth_header`), IPv4 Header (`struct ip_header`), TCP Header (`struct tcp_header`), UDP Header (`struct udp_header`).
   - Tối ưu hóa tính toán checksum và giải mã cờ TCP (SYN, ACK, FIN, RST, PSH, URG).
   - Tương tác với Python thông qua chuẩn FFI `ctypes`.
2. **Lớp Xử Lý Trung Tâm & Phát Hiện Bất Thường (Python Core)**:
   - Quét mạng đa luồng: ICMP Echo Request kết hợp ARP ping và TCP socket check.
   - Nhận diện hệ điều hành thiết bị (OS Fingerprinting) dựa trên phân tích thụ động TTL (Time-To-Live), dải cổng mở và OUI nhà sản xuất.
   - Giám sát kết nối chủ động (Active Connection Tracking): Trích xuất PID, tên tiến trình và lập bản đồ dịch vụ (Service Port Mapping).
3. **Lớp Trình Diễn & Phòng Vệ (Frontend & Defensive Layer)**:
   - Truyền tải thời gian thực bằng WebSocket hai chiều.
   - **Privacy Mode**: Che giấu địa chỉ IP (`***.***.***.***`), MAC (`••:••:••:••:••:••`), Gateway, Subnet và Public IP khi chia sẻ màn hình.
   - **Anti-Screenshot Red Shield**: Chặn phím tắt chụp màn hình (PrtScn, Win+Shift+S, Cmd+Shift+3/4, Ctrl+P) bằng lớp khiên đỏ cảnh báo và làm sạch clipboard.

---

## 🧪 5 BÀI THỰC HÀNH AN NINH MẠNG CHUYÊN SÂU (SECURITY LABS)

### BÀI 1: TẤN CÔNG ĐÁNH LỪA BẢNG ĐỆM ARP (ARP CACHE POISONING / MITM)
- **Lỗ Hổng (Vulnerability)**:
  Giao thức ARP (RFC 826) là giao thức phi trạng thái (Stateless), không có cơ chế xác thực nguồn gốc. Máy tính trong mạng LAN chấp nhận mọi gói tin ARP Reply ngay cả khi nó không hề gửi yêu cầu ARP Request trước đó.
- **Phương Thức Tấn Công (Attack Concept)**:
  Kẻ tấn công gửi liên tục các gói tin Gratuitous ARP giả mạo đến máy nạn nhân và Gateway:
  - Nói với nạn nhân: *"IP của Gateway (192.168.1.1) đang sở hữu địa chỉ MAC của Kẻ tấn công"*.
  - Nói với Gateway: *"IP của Nạn nhân (192.168.1.100) đang sở hữu địa chỉ MAC của Kẻ tấn công"*.
  Kết quả: Toàn bộ lưu lượng ra/vào mạng đều đi qua máy kẻ tấn công (Man-in-the-Middle).
- **Cơ Chế Phát Hiện (SOC Detection)**:
  Module giám sát liên tục theo dõi cặp `(IP, MAC)`. Khi một địa chỉ IP đột ngột trỏ về một địa chỉ MAC khác với bản ghi trước đó, hoặc một địa chỉ MAC sở hữu nhiều IP khác nhau một cách bất thường, hệ thống sẽ kích hoạt cảnh báo `ARP_SPOOFING` (Severity 3 - Critical).
- **Biện Pháp Phòng Ngừa (Mitigation)**:
  1. Bật tính năng **Dynamic ARP Inspection (DAI)** trên Managed Switch cùng với **DHCP Snooping**.
  2. Cấu hình bảng ARP tĩnh (`arp -s <ip> <mac>`) trên các máy chủ quan trọng và Default Gateway.
  3. Sử dụng chuẩn bảo mật mạng 802.1X để kiểm soát thiết bị cắm vào cổng vật lý.
- **Mã Nguồn Cấu Hình An Toàn (Secure Implementation)**:
  ```bash
  # Cấu hình trên Cisco Catalyst Switch:
  Switch(config)# ip dhcp snooping
  Switch(config)# ip dhcp snooping vlan 10
  Switch(config)# ip arp inspection vlan 10
  Switch(config)# interface GigabitEthernet0/1
  Switch(config-if)# ip arp inspection trust
  ```

---

### BÀI 2: KỸ THUẬT DÒ QUÉT CỔNG ẨN DANH & CỜ TCP BẤT THƯỜNG (TCP STEALTH SCAN)
- **Lỗ Hổng (Vulnerability)**:
  Theo chuẩn TCP RFC 793, nếu một cổng đóng nhận được gói tin không có cờ SYN hoặc ACK (như FIN, NULL, XMAS), hệ điều hành bắt buộc phải phản hồi bằng gói tin `RST`. Nếu cổng mở, hệ điều hành sẽ bỏ qua gói tin đó. Kẻ tấn công lợi dụng điều này để thăm dò cổng mà không cần hoàn tất bắt tay 3 bước (3-way handshake), tránh bị ghi log thông thường.
- **Phương Thức Tấn Công (Attack Concept)**:
  - **NULL Scan**: Gói tin TCP với toàn bộ 6 cờ đều tắt (`flags = 0x00`).
  - **XMAS Scan**: Bật đồng thời các cờ FIN, PSH, URG (`flags = 0x29`), làm gói tin "sáng rực như cây thông noel".
  - **FIN Scan**: Chỉ bật cờ FIN mà không có luồng kết nối trước đó.
- **Cơ Chế Phát Hiện (SOC Detection)**:
  Module C low-level `packet_parser.c` kiểm tra trực tiếp bitmask của trường `tcp_flags`:
  ```c
  if (tcp->th_flags == 0) {
      // Phát hiện NULL Scan
  }
  if ((tcp->th_flags & (TH_FIN | TH_PUSH | TH_URG)) == (TH_FIN | TH_PUSH | TH_URG)) {
      // Phát hiện XMAS Scan
  }
  ```
- **Biện Pháp Phòng Ngừa (Mitigation)**:
  1. Cấu hình Firewall ở chế độ Stateful Inspection (theo dõi trạng thái phiên).
  2. Bỏ qua các gói tin TCP không hợp lệ (INVALID state drop).
- **Mã Nguồn Cấu Hình An Toàn (Secure Implementation)**:
  ```bash
  # Cấu hình iptables/nftables chặn gói tin cờ bất thường:
  iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
  iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
  iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
  ```

---

### BÀI 3: THIẾT BỊ LẠ CẮM TRỘM VÀO MẠNG (ROGUE DEVICE DETECTION)
- **Lỗ Hổng (Vulnerability)**:
  Mạng nội bộ không áp dụng cơ chế xác thực lớp truy cập (Access Layer Authentication), cho phép bất kỳ thiết bị nào gắn dây LAN hoặc bắt Wi-Fi mở đều nhận được địa chỉ IP tự động từ DHCP.
- **Phương Thức Tấn Công (Attack Concept)**:
  Kẻ tấn công cắm thiết bị phần cứng kích thước nhỏ (ví dụ: Raspberry Pi Zero, LAN Turtle, WiFi Pineapple) vào một cổng mạng âm tường không dùng đến trong phòng họp hoặc hành lang công ty, thiết lập cầu nối ngược (Reverse Shell) về máy chủ ngoài internet.
- **Cơ Chế Phát Hiện (SOC Detection)**:
  Hệ thống duy trì danh bạ thiết bị trong bộ nhớ RAM (`DeviceStore`). Khi phát hiện một địa chỉ MAC chưa từng xuất hiện (`first_seen == last_seen`), hệ thống sẽ gửi cảnh báo `NEW_DEVICE_DISCOVERED` kèm định danh vendor OUI và ước lượng hệ điều hành.
- **Biện Pháp Phòng Ngừa (Mitigation)**:
  1. Triển khai **Port Security** trên Switch: Giới hạn số lượng MAC tối đa trên mỗi cổng (Max MAC = 1) và tự động shutdown cổng nếu phát hiện MAC lạ (`violation shutdown`).
  2. Áp dụng xác thực người dùng/thiết bị qua chuẩn **IEEE 802.1X (RADIUS / TACACS+)**.
  3. Vô hiệu hóa (Disable) tất cả các cổng mạng vật lý không có người sử dụng.
- **Mã Nguồn Cấu Hình An Toàn (Secure Implementation)**:
  ```bash
  # Cấu hình Port Security trên Switch:
  Switch(config)# interface GigabitEthernet 0/5
  Switch(config-if)# switchport mode access
  Switch(config-if)# switchport port-security
  Switch(config-if)# switchport port-security maximum 1
  Switch(config-if)# switchport port-security violation shutdown
  Switch(config-if)# switchport port-security mac-address sticky
  ```

---

### BÀI 4: KHAI THÁC DỊCH VỤ NGUY HIỂM & DI CHUYỂN NGANG (LATERAL MOVEMENT)
- **Lỗ Hổng (Vulnerability)**:
  Các giao thức quản trị và chia sẻ tài nguyên cũ không được mã hóa hoặc chứa lỗ hổng bảo mật nghiêm trọng:
  - `Port 23 (Telnet)`: Toàn bộ username/password truyền dạng clear-text (bản rõ).
  - `Port 445 (SMB)`: Tiềm ẩn các lỗ hổng thực thi mã từ xa (RCE) huyền thoại như EternalBlue (MS17-010).
  - `Port 3389 (RDP)`: Mục tiêu chính của các cuộc tấn công dò mật khẩu (Brute-force) hoặc BlueKeep (CVE-2019-0708).
- **Phương Thức Tấn Công (Attack Concept)**:
  Sau khi xâm nhập được vào một máy tính trong mạng LAN, kẻ tấn công thực hiện di chuyển ngang (Lateral Movement) sang các máy chủ kế bên bằng cách quét cổng 445/3389, khai thác lỗ hổng SMB v1 hoặc sử dụng thông tin đăng nhập đánh cắp được để điều khiển máy chủ tệp.
- **Cơ Chế Phát Hiện (SOC Detection)**:
  `ConnectionTracker` theo dõi mọi socket hoạt động của hệ điều hành. Khi phát hiện luồng dữ liệu kết nối tới danh sách cổng nguy hiểm (`23, 445, 3389, 6667, 4444...`), hệ thống phân tích PID, Process Name và kích hoạt cảnh báo `SUSPICIOUS_PORT`.
- **Biện Pháp Phòng Ngừa (Mitigation)**:
  1. Tắt bỏ hoàn toàn giao thức Telnet, thay thế bằng SSH (Port 22) có xác thực khóa công khai (Public Key).
  2. Vô hiệu hóa SMBv1 trên toàn bộ máy trạm Windows, chặn cổng 445 ở cấp độ tường lửa giữa các VLAN người dùng.
  3. Cấu hình xác thực đa yếu tố (MFA) cho dịch vụ Remote Desktop (RDP) và đặt sau VPN/Zero Trust Gateway.
- **Mã Nguồn Cấu Hình An Toàn (Secure Implementation)**:
  ```powershell
  # Vô hiệu hóa SMBv1 trên Windows PowerShell:
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

  # Chặn inbound SMB 445 bằng Windows Advanced Firewall:
  New-NetFirewallRule -Name "Block_Inbound_SMB" -DisplayName "Chặn Port 445 SMB Nội Bộ" `
      -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block
  ```

---

### BÀI 5: KẾT NỐI MÃ ĐỘC RA BÊN NGOÀI (C2 OUTBOUND BEACONING & DATA EXFILTRATION)
- **Lỗ Hổng (Vulnerability)**:
  Chính sách tường lửa nội bộ (Egress Firewall) thường quá lỏng lẻo: chỉ kiểm soát chiều vào (Inbound) mà cho phép toàn bộ lưu lượng chiều ra (Outbound Any Any).
- **Phương Thức Tấn Công (Attack Concept)**:
  Mã độc (Trojan, RAT) sau khi nằm vùng trên máy nạn nhân sẽ định kỳ phát tín hiệu "nhịp tim" (Beaconing) ra máy chủ điều khiển (Command and Control - C2 Server) qua các cổng lạ hoặc qua DNS Tunneling để nhận lệnh tấn công mới và tải dữ liệu nhạy cảm ra ngoài.
- **Cơ Chế Phát Hiện (SOC Detection)**:
  Hệ thống thống kê tốc độ truyền tải byte mạng đột biến và kiểm tra các kết nối hướng ra ngoài có đích IP công cộng không xác định, kết hợp hiển thị thông tin tiến trình thực thi (`process_name`) và PID.
- **Biện Pháp Phòng Ngừa (Mitigation)**:
  1. Áp dụng chính sách **Egress Filtering nghiêm ngặt**: Chỉ cho phép máy trạm kết nối ra ngoài qua Web Proxy (Port 80/443) và DNS Server nội bộ.
  2. Sử dụng giải pháp EDR (Endpoint Detection and Response) để giám sát các tiến trình không có chữ ký số tạo socket mạng.
  3. Triển khai DNS Sinkholing để cô lập các truy vấn tên miền độc hại đã biết.
- **Mã Nguồn Cấu Hình An Toàn (Secure Implementation)**:
  ```bash
  # Cấu hình tường lửa Linux chặn toàn bộ Outbound trừ cổng được phê duyệt:
  iptables -P OUTPUT DROP
  iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -p udp --dport 53 -d 1.1.1.1 -j ACCEPT
  iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
  ```

---

## 🛡️ HƯỚNG DẪN BẢO VỆ DỮ LIỆU & QUYỀN RIÊNG TƯ TRONG GIÁM SÁT MẠNG (PRIVACY-FIRST SOC)
1. **Nguyên Tắc Cần Biết Khi Chụp Ảnh Báo Cáo / Thuyết Minh**:
   - Không để lộ địa chỉ Public IP thực tế vì có thể dẫn tới các cuộc tấn công DDoS hoặc dò quét trực tiếp vào Router nhà mạng.
   - Không để lộ Gateway IP và Subnet nếu hệ thống đang hoạt động trên mạng doanh nghiệp thực tế.
   - Che giấu toàn bộ địa chỉ MAC (`••:••:••:••:••:••`) để tránh định danh chính xác thiết bị cá nhân.
2. **Kích Hoạt Chế Độ Bảo Mật Trên Network Monitor**:
   - Chế độ Privacy Mode được **bật mặc định ngay khi mở ứng dụng** để bảo vệ tức thì. Nhấp vào nút **"🔒 Hiện IP mạng"** trên thanh công cụ nếu bạn muốn xem bản rõ.
   - Trong quá trình trình chiếu, nếu có thao tác chụp ảnh màn hình vô tình kích hoạt, hệ thống sẽ dựng khiên đỏ bảo vệ để ngăn rò rỉ dữ liệu.
