# Network Security Monitor V1.3 - Zero-Footprint & In-Memory SOC

> 🛡️ **Hệ thống giám sát an ninh mạng LAN thời gian thực (Real-time LAN Security Monitor & Packet Analyzer)**  
> **Kiến trúc Zero-Footprint & In-Memory**: Hoạt động 100% trên bộ nhớ RAM — **Không tạo file database `data.db`, không dùng `.env`, không ghi log đĩa — Tắt ứng dụng là xóa sạch hoàn toàn mọi dấu vết.**

---

## 1. Triết Lý Thiết Kế: Zero-Footprint (Tắt Là Quên Sạch)

Hệ thống được tối ưu hóa đặc biệt theo tiêu chuẩn bảo mật & giáo dục an ninh mạng:
* **Không lưu database ra ổ cứng (`:memory:`)**: Toàn bộ dữ liệu thiết bị, phiên bắt gói tin, kết nối socket và sự kiện bảo mật được quản lý bằng bộ nhớ RAM.
* **Không cần file cấu hình `.env`**: Mọi thông số vận hành đã được lập trình sẵn giá trị mặc định tối ưu nhất, sẵn sàng chạy ngay mà không sinh bất kỳ file rác cấu hình nào.
* **Không ghi file log rác ra đĩa**: Toàn bộ nhật ký hoạt động được truyền trực tiếp ra Console / Terminal.
* **Bảo mật & Riêng tư tuyệt đối**: Khi bạn nhấn `Ctrl + C` hoặc đóng cửa sổ chương trình, hệ điều hành tự động thu hồi RAM. **Không một byte dữ liệu nào bị lưu lại trên máy tính.**
* **Khởi động thông minh chống xung đột cổng**: Tự động phát hiện cổng bận và chuyển đổi cổng khả dụng (8000, 8001...) để ngăn chặn hoàn toàn lỗi `[Errno 10048]`.

---

## 2. Điểm Mới Trong Phiên Bản V1.3 (New Features)

1. 🛡️ **Privacy Mode (Chế độ riêng tư toàn diện)**:
   - Che giấu địa chỉ IP (`***.***.***.***`), MAC (`••:••:••:••:••:••`), Gateway, Subnet và Public IP.
   - Giúp giảng viên, sinh viên và kỹ sư an toàn quay video demo hoặc thuyết trình mà không lo lộ cấu trúc mạng.
2. 📱 **Nhận Diện Hệ Điều Hành & Loại Thiết Bị (Device & OS Fingerprinting)**:
   - Tự động phân tích TTL (Time-To-Live), dải cổng dịch vụ và Vendor OUI để ước lượng hệ điều hành: **Windows**, **Linux**, **Apple (macOS / iOS)**, **Android**, **RouterOS / Gateway**, **IoT**.
   - Phân loại rõ ràng icon: Máy tính, Điện thoại, Smart TV, Camera IP, Router, Thiết bị Smart Home.
3. 🌐 **Thông Tin Chi Tiết Card Mạng (Wi-Fi & Ethernet Adapter Specs)**:
   - Tự động nhận diện chuẩn kết nối vật lý: Wi-Fi (802.11) hoặc Ethernet (802.3).
   - Với Wi-Fi: Trích xuất trực tiếp tên mạng SSID, địa chỉ BSSID của Access Point, cường độ sóng (Signal %), loại sóng (Radio type) và tốc độ truyền nhận dữ liệu (Rx/Tx Mbps).
   - Với Ethernet: Hiển thị tốc độ Gigabit/Fast Ethernet, chế độ truyền Duplex (Full/Half) và MTU.
4. 🌍 **Tra Cứu Nhà Mạng & Public IP (Opt-In Consent Model)**:
   - Tuân thủ nghiêm ngặt quyền riêng tư: **Chỉ tra cứu khi người dùng chủ động nhấp nút đồng ý**.
   - Cung cấp thông tin nhà cung cấp dịch vụ Internet (ISP), số hiệu mạng ASN, địa chỉ Public IP thực tế và vị trí địa lý.
5. 🔌 **Theo Dõi Kết Nối Socket Kèm Tên Dịch Vụ (Service Mapping)**:
   - Hiển thị chi tiết: IP:Port nguồn, IP:Port đích, Giao thức TCP/UDP, Tên dịch vụ chuẩn hóa (HTTP, HTTPS, DNS, SSH, SMB, RDP...), Trạng thái phiên (ESTABLISHED, LISTEN, CLOSE_WAIT...), Tên tiến trình (`process_name`) và PID.
6. 🧪 **Phòng Thí Nghiệm An Ninh Mạng Tương Tác (Security Lab Mode)**:
   - Tích hợp 5 bài thực hành an ninh mạng theo chuẩn SOC quốc tế:
     1. **Bài 1**: ARP Cache Poisoning & Man-In-The-Middle (MITM).
     2. **Bài 2**: TCP Stealth Scan (NULL, XMAS, FIN flags scan).
     3. **Bài 3**: Rogue Device Detection & DHCP Hijacking.
     4. **Bài 4**: Khai thác dịch vụ nhạy cảm & Lateral Movement (SMB 445, Telnet 23, RDP 3389).
     5. **Bài 5**: C2 Outbound Beaconing & Data Exfiltration.
   - Mỗi bài lab đều có cấu trúc 5 bước hoàn chỉnh: **Lỗ hổng (Vulnerability) → Phương thức tấn công (Attack Concept) → Cơ chế phát hiện (SOC Detection) → Biện pháp phòng ngừa (Mitigation) → Mã nguồn cấu hình an toàn (Secure Implementation)**.
   - Đi kèm nút **"▶️ Chạy Mô Phỏng"** an toàn trên localhost để kiểm tra phản hồi của SOC.
7. 🚨 **Khiên Đỏ Cảnh Báo Chống Chụp Màn Hình (Anti-Screenshot Red Shield)**:
   - Tự động kích hoạt khi phát hiện thao tác `PrintScreen`, `Win + Shift + S`, Snipping Tool, MacOS `Cmd + Shift + 3/4`, In ấn `Ctrl + P`.
   - Phủ kín màn hình bằng nền đỏ cảnh báo, làm sạch clipboard và đếm ngược 3 giây xác nhận an toàn.

---

## 3. Ngăn Xếp Công Nghệ (Tech Stack)

* **Backend Core**: Python 3.11+ (FastAPI + AsyncIO + Uvicorn).
* **Low-Level C Module**: Module C cấp thấp (`packet_parser.c`) bóc tách header nhị phân Ethernet / IPv4 / TCP / UDP với ctypes FFI bridge.
* **Storage**: In-Memory Data Store thuần Python (Zero Disk IO, 100% RAM).
* **Network & Security Services**:
  * `psutil` & `netsh wlan` / `nmcli`: Thu thập socket, tiến trình và thông số Wi-Fi/Ethernet.
  * Scapy + Npcap / libpcap: Packet sniffer tầng liên kết dữ liệu.
  * Ping Sweep đa luồng kết hợp đọc bảng ARP hệ thống.
  * IEEE OUI Vendor Database.
* **Frontend**: Vanilla Web (HTML5 + CSS3 Glassmorphism Dark Mode + JavaScript thuần ES6 + Chart.js via CDN). Không cần build npm.

---

## 4. Cấu Trúc Mã Nguồn

```
network-monitor/
├── backend/                       # Máy chủ Backend (FastAPI + C Module)
│   ├── api/                       # Router REST API & WebSocket
│   │   ├── connections.py         #   /api/connections
│   │   ├── devices.py             #   /api/devices
│   │   ├── events.py              #   /api/events
│   │   ├── lab.py                 #   /api/lab & /api/lab/simulate/{lab_id}
│   │   ├── network.py             #   /api/network, /api/network/adapter, /api/network/isp-lookup
│   │   ├── packets.py             #   /api/packets
│   │   ├── security.py            #   /api/security/events
│   │   ├── stats.py               #   /api/stats
│   │   └── websocket.py           #   /ws/dashboard
│   │
│   ├── c_modules/                 # Module C cấp thấp bóc tách gói tin
│   │   ├── packet_parser.c        #   Mã nguồn C phân tích packet
│   │   ├── packet_parser.h        #   Khai báo C Struct
│   │   ├── build_c.py             #   Script tự biên dịch DLL/SO
│   │   └── c_parser_bridge.py     #   CTypes bridge & fallback thuần Python
│   ├── memory_store.py            #   Bộ nhớ tạm thời thuần Python RAM - Tắt là quên sạch
│   ├── services/                  # Các dịch vụ nền
│   │   ├── connection_tracker.py  #   Theo dõi Socket, Process & Port Service Mapping
│   │   ├── interface_info.py      #   Trích xuất thông số Wi-Fi / Ethernet adapter
│   │   ├── monitor_manager.py     #   Bộ điều phối trung tâm
│   │   ├── network_info.py        #   Nhận diện IP, Gateway, Subnet & Tra cứu ISP Opt-in
│   │   ├── packet_sniffer.py      #   Thu thập & giải mã packet
│   │   ├── ping_service.py        #   Ping ICMP & ARP Table kèm trích xuất TTL
│   │   ├── scanner.py             #   Dò quét mạng LAN, Port & Nhận diện OS Fingerprinting
│   │   ├── security_engine.py     #   Phát hiện bất thường an ninh mạng
│   │   ├── traffic_monitor.py     #   Lấy mẫu băng thông mạng thời gian thực
│   │   ├── vendor_lookup.py       #   Tra cứu hãng MAC OUI
│   │   └── websocket_manager.py   #   Quản lý kết nối WebSocket
│   │
│   ├── config.py                  # Cấu hình mặc định (không cần .env)
│   ├── logging_config.py          # Log console (không tạo file đĩa)
│   └── main.py                    # Khởi tạo FastAPI App
│
├── frontend/                      # Giao diện SOC Dashboard thời gian thực
│   ├── css/style.css              #   Glassmorphism Dark Theme & Viettel Router Design
│   ├── js/app.js                  #   WebSocket client, Privacy manager & Lab runner
│   └── index.html                 #   Trang chủ điều hành 6 Tab
│
├── docs/                          # Tài liệu kỹ thuật
│   ├── ARCHITECTURE_ROADMAP.md    #   Bản đồ kiến trúc hệ thống
│   └── NETWORK_SECURITY_CURRICULUM.md # Giáo trình an ninh mạng & 5 bài Lab chuyên sâu
│
├── .gitignore                     # Bỏ qua file rác
├── requirements.txt               # Thư viện Python tối giản
├── run.py                         # Trình khởi động thông minh 1-Click (Tự tránh xung đột cổng)
└── start.bat                      # File khởi động nhanh trên Windows
```

---

## 5. Hướng Dẫn Khởi Động (Chỉ 1 Thao Tác)

### Cách 1: Dành cho Windows (Khuyên Dùng)
Nhấp đúp chuột vào file:
```bat
start.bat
```

### Cách 2: Khởi động qua Terminal
```bash
python run.py
```

### Điểm Vượt Trội Khi Khởi Động
1. Script tự động kiểm tra cổng khả dụng (nếu cổng 8000 đã có ứng dụng khác chiếm dụng, script tự động chọn cổng 8001, 8002... mà không bao giờ bị crash).
2. Tự kiểm tra và cài đặt nhanh các thư viện nếu máy tính còn thiếu (`fastapi`, `uvicorn`, `psutil`, `scapy`...).
3. Tự động mở trình duyệt web:
   * **Dashboard SOC**: `http://localhost:8000` (hoặc cổng tự động gán)
   * **Swagger API Docs**: `http://localhost:8000/docs`
4. **Tắt ứng dụng**: Nhấn `Ctrl + C` trong cửa sổ console. Toàn bộ dữ liệu bộ nhớ RAM lập tức được xóa sạch.

---

## 6. Danh Mục API Endpoints V1.3

| Phương thức | Endpoint | Chức năng |
| :---: | :--- | :--- |
| `GET` | `/api/health` | Kiểm tra trạng thái máy chủ |
| `GET` | `/api/stats` | Thống kê số lượng thiết bị, uptime, tốc độ mạng, latency |
| `GET` | `/api/network` | Lấy IP nội bộ, Gateway, Subnet, DNS |
| `GET` | `/api/network/adapter` | Lấy chi tiết Card mạng: Wi-Fi (SSID, BSSID, Signal %, Speed) / Ethernet (Gigabit, Duplex, MTU) |
| `POST`| `/api/network/isp-lookup` | Tra cứu nhà mạng ISP, ASN, Public IP (Người dùng chủ động nhấn cho phép) |
| `GET` | `/api/devices` | Danh sách thiết bị LAN kèm OS badge, Vendor, Port mở, Ping |
| `POST`| `/api/devices/scan` | Yêu cầu quét dải mạng LAN mới ngay lập tức |
| `PATCH`| `/api/devices/{mac}` | Sửa tên gợi nhớ hoặc loại thiết bị |
| `GET` | `/api/connections` | Danh sách Socket TCP/UDP đang hoạt động kèm tên Dịch vụ & Tiến trình |
| `GET` | `/api/packets` | Danh sách gói tin bắt được gần nhất |
| `GET` | `/api/security/events` | Danh sách sự kiện cảnh báo an ninh SOC |
| `GET` | `/api/lab` | Danh sách 5 bài thực hành an ninh mạng chi tiết |
| `POST`| `/api/lab/simulate/{lab_id}` | Kích hoạt mô phỏng an ninh mạng an toàn trên localhost |
| `WS`  | `/ws/dashboard` | Kênh WebSocket truyền dữ liệu thời gian thực lên giao diện |

---

## 7. Tài Liệu Nghiên Cứu Chuyên Sâu

* **Giáo trình đào tạo an ninh mạng**: Đọc ngay tại [docs/NETWORK_SECURITY_CURRICULUM.md](file:///e:/network-monitor/docs/NETWORK_SECURITY_CURRICULUM.md)
* **Bản đồ kiến trúc hệ thống**: Xem tại [docs/ARCHITECTURE_ROADMAP.md](file:///e:/network-monitor/docs/ARCHITECTURE_ROADMAP.md)
