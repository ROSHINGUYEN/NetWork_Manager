"""
Network Monitor - Launcher tự động hóa (1-Click Zero-Footprint Startup Script)
Tự động kiểm tra thư viện, mở máy chủ và tự bật trình duyệt.
Chế độ In-Memory: Không tạo file database, không cần file .env, không lưu log đĩa.
Tắt là xóa sạch hoàn toàn khỏi bộ nhớ.
"""

import os
import sys
import time
import webbrowser
import subprocess
from threading import Timer
from pathlib import Path

# Đảm bảo stdout/stderr hỗ trợ an toàn mọi bảng mã trên Windows CMD / PowerShell
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent

REQUIRED_PACKAGES = [
    ("fastapi", "fastapi"),
    ("uvicorn", "uvicorn[standard]"),
    ("websockets", "websockets"),
    ("psutil", "psutil"),
    ("scapy", "scapy"),
]


def check_and_install_packages():
    """Tự động kiểm tra và cài đặt các thư viện cần thiết nếu còn thiếu."""
    missing = []
    for module_name, pip_name in REQUIRED_PACKAGES:
        try:
            __import__(module_name)
        except ImportError:
            missing.append(pip_name)

    if missing:
        print("=" * 65)
        print(" [!] Dang tu dong cai dat thu vien:", ", ".join(missing))
        print(" Vui long cho trong giay lat...")
        print("=" * 65)
        cmd = [sys.executable, "-m", "pip", "install"] + missing
        try:
            subprocess.check_call(cmd)
            print(">> Cai dat thu vien thanh cong!\n")
        except Exception as e:
            print(f"[Canh bao] Khong the tu dong cai dat: {e}")
            print("Ban co the cai dat thu cong bang lenh: pip install -r requirements.txt")


def open_browser(url: str):
    """Mở trình duyệt sau khi máy chủ đã sẵn sàng."""
    time.sleep(1.2)
    try:
        webbrowser.open(url)
    except Exception:
        pass


def print_banner(host: str, port: int):
    print("\n" + "=" * 65)
    print("      NETWORK MONITOR - HE THONG GIAM SAT MANG LAN REALTIME")
    print("      [Che do: In-Memory / Khong luu dia / Tat la quen sach]")
    print("=" * 65)
    print(f" * Dashboard Web:   http://localhost:{port}")
    print(f" * Mang noi bo LAN: http://{host}:{port}")
    print(f" * REST API Docs:   http://localhost:{port}/docs")
    print("-" * 65)
    print(" >> Nhan Ctrl + C trong cua so nay de tat ung dung an toan.")
    print("=" * 65 + "\n")


def find_available_port(host: str, start_port: int = 8000) -> int:
    """Tự động tìm kiếm cổng còn trống, tránh lỗi Errno 10048 khi cổng bị chiếm dụng."""
    import socket
    port = start_port
    for p in range(start_port, start_port + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, p))
                return p
            except OSError:
                continue
    return start_port


def main():
    check_and_install_packages()

    # Nạp uvicorn và config
    import uvicorn
    from backend.config import settings

    target_host = settings.HOST or "0.0.0.0"
    base_port = settings.PORT or 8000
    port = find_available_port(target_host, base_port)

    if port != base_port:
        print(f" [!] Cong {base_port} dang duoc su dung boi tien trinh khac.")
        print(f" [*] He thong tu dong chuyen sang cong trong: {port}")

    # Hẹn giờ tự bật trình duyệt
    Timer(1.5, open_browser, args=[f"http://localhost:{port}"]).start()

    print_banner(target_host, port)

    try:
        uvicorn.run(
            "backend.main:app",
            host=target_host,
            port=port,
            reload=False,
            log_level=settings.LOG_LEVEL.lower(),
        )
    except KeyboardInterrupt:
        print("\n>> Da tat Network Monitor. Toan bo du lieu da duoc xoa sach khoi RAM.")


if __name__ == "__main__":
    main()
