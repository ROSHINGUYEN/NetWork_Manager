import os
import subprocess
import platform
import logging
from pathlib import Path

logger = logging.getLogger("network_monitor.c_build")
logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).resolve().parent

def find_compiler():
    """Tìm trình biên dịch C (gcc, clang, cl) trên hệ thống."""
    compilers = ["gcc", "clang"]
    if platform.system() == "Windows":
        compilers.append("cl")  # MSVC
        
    for comp in compilers:
        try:
            subprocess.run([comp, "--version" if comp != "cl" else ""], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return comp
        except FileNotFoundError:
            continue
    return None

def build_packet_parser():
    """Biên dịch mã C thành thư viện dùng chung (DLL/SO)."""
    compiler = find_compiler()
    if not compiler:
        logger.warning("Không tìm thấy trình biên dịch C (gcc, clang, cl) trên máy tính.")
        logger.warning("Network Security Monitor sẽ tự động sử dụng bộ giả lập Python 100% thay thế.")
        return False

    c_file = BASE_DIR / "packet_parser.c"
    
    if platform.system() == "Windows":
        out_file = BASE_DIR / "packet_parser.dll"
        if compiler == "cl":
            cmd = [compiler, "/LD", str(c_file), f"/Fe{out_file}"]
        else:
            cmd = [compiler, "-shared", "-o", str(out_file), str(c_file)]
    else:
        out_file = BASE_DIR / "packet_parser.so"
        cmd = [compiler, "-shared", "-fPIC", "-o", str(out_file), str(c_file)]

    logger.info(f"Đang biên dịch C module với trình biên dịch: {compiler}")
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0:
            logger.info(f"Biên dịch thành công: {out_file.name}")
            return True
        else:
            logger.error(f"Lỗi biên dịch: {res.stderr}")
            return False
    except Exception as e:
        logger.error(f"Lỗi hệ thống khi chạy trình biên dịch: {e}")
        return False

if __name__ == "__main__":
    build_packet_parser()
