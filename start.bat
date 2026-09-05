@echo off
title Network Monitor
cls
echo =======================================================================
echo              DANG KHOI DONG NETWORK MONITOR...
echo =======================================================================
echo.
echo   * Dang kiem tra moi truong Python va thu vien...
echo   * Ung dung se tu dong mo trinh duyet web tai http://localhost:8000
echo.
echo =======================================================================
python run.py
if errorlevel 1 (
    echo.
    echo [LOI] Khong the khoi dong chuong trinh. Hay chac chan Python da duoc cai dat.
    echo.
    pause
)
