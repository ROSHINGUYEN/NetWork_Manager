<div align="center">

# 🌐 NETWORK MANAGER

### HỆ THỐNG QUẢN LÝ MẠNG LAN
**Real-time LAN Device Management & Security Monitoring Dashboard**

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Backend](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi&logoColor=white)
![Parser](https://img.shields.io/badge/Packet%20Parser-C%20(ctypes)-A8B9CC?logo=c&logoColor=black)
![Frontend](https://img.shields.io/badge/Frontend-Vanilla%20JS%20%2B%20Chart.js-F7DF1E?logo=javascript&logoColor=black)
![Realtime](https://img.shields.io/badge/Realtime-WebSocket-010101?logo=socketdotio&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows11&logoColor=white)
![Language UI](https://img.shields.io/badge/Giao%20di%E1%BB%87n-Ti%E1%BA%BFng%20Vi%E1%BB%87t%20%F0%9F%87%BB%F0%9F%87%B3-DD0031)
![Mục đích](https://img.shields.io/badge/M%E1%BB%A5c%20%C4%91%C3%ADch-Gi%C3%A1o%20d%E1%BB%A5c%20%26%20SOC-2EA043)
![License](https://img.shields.io/badge/License-MIT-8A2BE2?logo=openaccessinitiative&logoColor=white)

📸 **Ảnh demo — Trang quản lý thiết bị mạng (IP/MAC được Privacy Mode tự động che):**

![Demo — Danh sách thiết bị kết nối (LAN Clients)](docs\images\dashboard-lan-clients.png)

*Giao diện mô phỏng chuẩn trang quản trị **Modem GPON Gateway** (phong cách Viettel Telecom).*

</div>

> ⚙️ **Kiến trúc Zero-Footprint & In-Memory SOC**: Hoạt động 100% trên bộ nhớ RAM — **không tạo `data.db`, không dùng `.env`, không ghi log đĩa — tắt ứng dụng là xóa sạch hoàn toàn mọi dấu vết.**

-----------

## 1. Tính Năng Nổi Bật 

### 📱 Quét & Quản Lý Thiết Bị LAN (LAN Clients)
> 📸 *Ảnh demo chính ở đầu trang — Tab "Danh sách thiết bị kết nối"*

- Quét toàn bộ dải mạng (VD: `192.168.1.0/24`) bằng **Ping Sweep đa luồng** kết hợp bảng ARP & TCP socket check.
- Bảng dữ liệu trực tiếp: **Trạng thái • Tên thiết bị & Ghi nhớ • Địa chỉ IP • Địa chỉ MAC • Hãng sản xuất (OUI) • Hệ điều hành (OS) • Cổng mở • Độ trễ (ms)**.
- **Nhận diện hệ điều hành tự động** (TTL + cổng đặc trưng + OUI): `Windows 10/11`, `Android OS`, `RouterOS / Linux Embedded`, `Embedded Linux (IP Camera)`, `FreeRTOS / Embedded IoT`...
- ✏️ Đặt **tên thân thiện** cho từng thiết bị (VD: *"Camera phòng khách"*, *"iPhone của Nam"*) — ghi nhớ trong bộ nhớ phiên.
- Bộ lọc nhanh `Tất cả (6) / Đang Online / Đã Offline` + ô tìm kiếm theo IP, tên, hãng, MAC.
- Nút **"🔄 Quét mạng ngay"** và ô **"Dải IP quét"** tùy chỉnh (tự động điền dải LAN hiện tại).

----------
### 2 🔒 Privacy Mode — Ẩn IP Tự Động (Bảo Vệ Ảnh Chụp Màn Hình)

- **Ẩn mặc định 100%**: IP → `***.***.***.***`, MAC → `••:••:••:••:••:••`, Gateway / Subnet / Public IP đều được che.
- Badge header **`Privacy: AUTO ẨN IP`** hiển thị tình trạng bảo vệ theo thời gian thực.
- ⚡ **Tự động kích hoạt khi có rủi ro rò rỉ**: ngay khi cửa sổ **mất tiêu điểm** (mở Snipping Tool `Win+Shift+S`, trình quay màn hình, chuyển tab/ứng dụng, bật chia sẻ màn hình họp trực tuyến), hệ thống **ẩn lại toàn bộ IP TRƯỚC khi ảnh chụp/chia sẻ kịp thu được hình** → mọi ảnh chụp chỉ thấy địa chỉ đã che, vô dụng với kẻ thu thập thông tin.
- Nút **"🔒 Hiện IP mạng"** để xem bản rõ tạm thời; bấm lần nữa để ẩn lại.
- ℹ️ *Vì sao thiết kế này?* Trình duyệt không thể chặn cơ chế chụp màn hình của hệ điều hành (ảnh `PrtScn` đã vào clipboard trước khi trang nhận sự kiện phím) — nên hệ thống bảo vệ **dữ liệu bên trong ảnh** thay vì lớp phủ "chặn chụp" vô hiệu.

-----------------

### 3 🌐 Thông Tin Chi Tiết Card Mạng (Wi-Fi / Ethernet Adapter)

- **Wi-Fi**: SSID, BSSID của Access Point, cường độ sóng (%), chuẩn Radio (802.11), tốc độ Rx/Tx Mbps.
- **Ethernet**: tốc độ Gigabit/Fast Ethernet, chế độ Full/Half Duplex, MTU.

----------------

### 4 📊 Thống Kê Lưu Lượng & Băng Thông Thời Gian Thực

- Biểu đồ **Chart.js** mượt mà: băng thông tải xuống / tải lên lấy mẫu liên tục theo card mạng.
- Thẻ tóm tắt đầu trang: `Kết nối Internet` • `Cổng Gateway (Router)` • `Thiết bị hoạt động 6/6 Online` • `Băng thông máy chủ ↓↑`.

----------------

### 5 🔌 Giám Sát Kết Nối & Gói Tin (L3/L4)

- Toàn bộ socket **TCP/UDP** đang hoạt động kèm **tên dịch vụ chuẩn hóa** (HTTP, HTTPS, DNS, SMB, RDP...), **tên tiến trình + PID**.
- Bắt & giải mã **gói tin thời gian thực** (module C cấp thấp + Scapy), gắn cờ gói bất thường.

----

### 6 🛡️ Trung Tâm An Ninh Mạng (SOC)

- **Tự động phát hiện & cảnh báo**: thiết bị mới xuất hiện, thiết bị mở cổng nguy hiểm (`Telnet 23`, `SMB 445`, `RDP 3389`), hành vi dò quét, bất thường ARP...
- Phân loại mức độ: **Thông tin / Cảnh báo / Nghiêm trọng** kèm bộ đếm tổng quan.

---

### 7 🌍 Tra Cứu Nhà Mạng & Public IP (Opt-In Consent)

- Tuân thủ quyền riêng tư: **chỉ tra cứu khi bạn chủ động bấm nút đồng ý**.
- Trả về: Nhà mạng (ISP), số hiệu ASN, Public IP thực tế, vị trí địa lý.

---

## 8. Sơ Đồ 6 Tab Điều Hành (Theo Giao Diện Thật)

| Tab | Tên hiển thị trên giao diện | Chức năng chính |
| :-: | :--- | :--- |
| 1 | 📱 **Danh sách thiết bị kết nối (LAN Clients)** | Quét dải IP, liệt kê thiết bị, OS fingerprint, đặt tên thân thiện, Privacy Mode |
| 2 | 📊 **Thống kê lưu lượng & Băng thông** | Biểu đồ băng thông real-time, thông số card Wi-Fi/Ethernet |
| 3 | 🔌 **Giám sát Kết nối & Gói tin (L3/L4)** | Socket + tiến trình + dịch vụ; bảng gói tin bắt được |
| 4 | 🛡️ **Trung tâm An ninh Mạng (SOC)** | Sự kiện cảnh báo an ninh thời gian thực |
| 5 | 📋 **Nhật ký hệ thống (System Logs)** | Nhật ký hoạt động của máy chủ |

---

## 9. Ngăn Xếp Công Nghệ (Tech Stack)

| Thành phần | Công nghệ |
| :--- | :--- |
| Backend Core | Python 3.11+ — **FastAPI + AsyncIO + Uvicorn** |
| Packet Parser | Module **C** cấp thấp (`packet_parser.c`) bóc tách header Ethernet/IPv4/TCP/UDP qua **ctypes FFI** (có fallback thuần Python) |
| Storage | **In-Memory Data Store** thuần Python (Zero Disk I/O, 100% RAM) |
| Mạng & An ninh | `psutil`, `netsh wlan`/`nmcli`, **Scapy + Npcap/libpcap**, Ping Sweep đa luồng + ARP, IEEE OUI Vendor DB |
| Frontend | Vanilla HTML5 + CSS3 (Glassmorphism Dark) + JavaScript ES6 + **Chart.js** (CDN) — không cần build npm |
| Truyền dữ liệu | REST API + **WebSocket** hai chiều thời gian thực |

---

## 10. Cài Đặt & Khởi Động (Chỉ 1 Thao Tác)

### 📋 Yêu cầu hệ thống
| Yêu cầu | Chi tiết |
| :--- | :--- |
| Hệ điều hành | Windows 10/11 (khuyên dùng); Linux hỗ trợ cơ bản |
| Python | **3.11+** |
| Đặc quyền | Chạy bằng **Run as Administrator** để bắt gói tin & quét LAN chính xác |
| Bắt gói tin | Cài **[Npcap](https://npcap.com/#download)** (Windows) / `libpcap` (Linux) |
| Trình duyệt | Chrome / Edge / Firefox bản mới nhất |

### 🚀 Khởi động qua Terminal (Khuyên dùng kèm quyền Administrator)
```bash
python run.py
```

### ✨ Script khởi động tự động:
1. Kiểm tra & **tự cài thư viện còn thiếu** (`fastapi`, `uvicorn`, `psutil`, `scapy`...).
2. **Tự tránh xung đột cổng**: nếu cổng 8000 bận, tự chuyển sang 8001, 8002... (không bao giờ lỗi `[Errno 10048]`).
3. Tự mở trình duyệt:
   - 🖥️ **Trang Quản Lý Mạng LAN**: `http://localhost:8000`
   - 📚 **Swagger API Docs**: `http://localhost:8000/docs`
4. 🛑 **Tắt ứng dụng**: nhấn `Ctrl + C` — toàn bộ dữ liệu RAM được xóa sạch ngay lập tức.

---

## 11. Hướng Dẫn Sử Dụng Chi Tiết

### Bước 1 — Quét mạng LAN
1. Mở tab **"📱 Danh sách thiết bị kết nối (LAN Clients)"**.
2. Hệ thống **tự quét định kỳ**; muốn quét ngay, nhập dải IP vào ô **"Dải IP quét"** (VD: `192.168.1.0/24`) rồi bấm nút đỏ **"🔄 Quét mạng ngay"**.
3. Kết quả hiện bảng: trạng thái, IP, MAC, hãng sản xuất, hệ điều hành, cổng mở, độ trễ.

### Bước 2 — Đặt tên thân thiện cho thiết bị
- Nhấp nút **✏️** ở cuối mỗi dòng thiết bị → nhập tên gợi nhớ (VD: *"Camera phòng khách"*) → Lưu.

### Bước 3 — Dùng Privacy Mode (Che IP)
- **Mặc định IP đã được ẩn** (`***.***.***.***`).
- Muốn xem bản rõ: bấm **"🔒 Hiện IP mạng"** → bấm lần nữa để ẩn lại.
- **Tự động bảo vệ**: khi bạn chụp màn hình, chia sẻ màn hình hoặc chuyển tab/ứng dụng (cửa sổ mất tiêu điểm), hệ thống **tự động ẩn lại toàn bộ IP** — ảnh chụp chỉ thu được địa chỉ đã che. Badge `Privacy: AUTO ẨN IP` trên header luôn báo trạng thái.

### Bước 4 — Xem lưu lượng & thông tin card mạng
- Vào tab **"📊 Thống kê lưu lượng & Băng thông"**: biểu đồ real-time ↓↑, thông số Wi-Fi (SSID, BSSID, sóng %) hoặc Ethernet (Gigabit, Duplex, MTU).

### Bước 5 — Giám sát kết nối & gói tin
- Tab **"🔌 Giám sát Kết nối & Gói tin"**: xem socket TCP/UDP kèm tiến trình, dịch vụ; bảng gói tin bắt được thời gian thực (cần chạy với Administrator + Npcap).

### Bước 6 — Theo dõi cảnh báo an ninh (SOC)
- Tab **"🛡️ Trung tâm An ninh Mạng (SOC)"**: cảnh báo thiết bị lạ, cổng nguy hiểm, dò quét... theo 3 mức Thông tin / Cảnh báo / Nghiêm trọng.

### Bước 7 — Tra cứu nhà mạng (tùy chọn)
- Chỉ khi bạn **chủ động bấm đồng ý**: hệ thống tra cứu ISP, ASN, Public IP, vị trí của đường mạng hiện tại.

---

## 12. Xử Lý Sự Cố (Troubleshooting)

| Hiện tượng | Nguyên nhân & Cách xử lý |
| :--- | :--- |
| Không quét được thiết bị / không bắt gói tin | Chưa chạy **Administrator** hoặc chưa cài **Npcap** → cài Npcap rồi chạy lại với quyền Admin |
| Cổng 8000 bị chiếm (`Errno 10048`) | Script **tự động chuyển cổng** 8001, 8002... — xem cổng thực tế in trong console |
| WebSocket hiện `● Mất kết nối...` | Server vừa khởi động lại → trang **tự kết nối lại sau 3 giây**; nếu không được, F5 trình duyệt |
| Không thấy SSID/băng thông Wi-Fi | Card không hỗ trợ `netsh wlan show interfaces` → kiểm tra bằng lệnh này thủ công |
| Ảnh chụp vẫn thấy IP | Kiểm tra badge `Privacy: AUTO ẨN IP` — nếu đang hiện `Hiện IP mạng` nghĩa là bạn đã tắt chế độ ẩn, bấm lại nút 🔒 |

---

## 13. Giấy Phép (License)

Dự án được phát hành theo giấy phép **MIT** — xem toàn văn tại [LICENSE](LICENSE).

> ⚠️ Dự án phục vụ **mục đích giáo dục an ninh mạng & quản trị mạng cá nhân**. Vui lòng chỉ sử dụng trên mạng LAN của chính bạn hoặc môi trường được cấp phép. Tác giả không chịu trách nhiệm với bất kỳ hành vi lạm dụng nào.

<div align="center">

**NETWORK MANAGER** — Hệ Thống Quản Lý Mạng LAN 🇻🇳

</div>
