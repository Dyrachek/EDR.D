import flet as ft
import threading
import sys
import os
import winreg
from core.monitor import ProcessMonitor
from ui.app import MiniEDRApp

APP_NAME = "MEDR.D"
EXE_PATH = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0])

def is_autostart_enabled():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_READ
        )
        winreg.QueryValueEx(key, APP_NAME)
        winreg.CloseKey(key)
        return True
    except:
        return False

def set_autostart(enable: bool):
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        0, winreg.KEY_SET_VALUE
    )
    try:
        if enable:
            if getattr(sys, 'frozen', False):
                value = f'"{EXE_PATH}"'
            else:
                value = f'"{sys.executable}" "{os.path.abspath("main.py")}"'
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, value)
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass
    finally:
        winreg.CloseKey(key)

def main():
    monitor = ProcessMonitor()

    monitor_thread = threading.Thread(target=monitor.start, daemon=True)
    monitor_thread.start()

    def run_ui(page: ft.Page):
        app = MiniEDRApp(page, monitor)
        app.build()

    ft.run(
        run_ui,
        assets_dir="assets",
    )

if __name__ == "__main__":
    main()