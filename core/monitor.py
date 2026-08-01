import psutil
import time
import json
import os
import winreg
from threading import Lock
from datetime import datetime

ALERTS_FILE = "alerts_history.json"
WHITELIST_FILE = "whitelist.json"

class ProcessMonitor:
    def __init__(self):
        self.processes = []
        self.connections = []
        self.system_info = {"cpu": 0.0, "memory": 0.0, "disk": 0.0}
        self.alerts = []
        self.alerts_history = []
        self.lock = Lock()
        self.running = False
        self.seen_alerts = set()
        self.whitelist = self._load_whitelist()

        self.suspicious_keywords = [
            "powershell", "cmd.exe", "rundll32", "regsvr32", "mshta",
            "wscript", "cscript", "certutil", "bitsadmin", "mimikatz",
            "nc.exe", "ncat", "netcat", "whoami", "psexec", "procdump",
            "ransom", "cryptor", "keylogger"
        ]

        self.suspicious_paths = [
            r"\temp\\",
            r"\appdata\local\temp\\",
            r"\downloads\\",
            r"\appdata\roaming\\",
            r"\users\public\\",
        ]

        self.safe_processes = [
            "system idle process", "system", "registry", "smss.exe",
            "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
            "svchost.exe", "explorer.exe", "dwm.exe", "fontdrvhost.exe"
        ]

        self._load_history()

        for proc in psutil.process_iter(["pid"]):
            try:
                proc.cpu_percent(interval=None)
            except Exception:
                pass

    def _load_history(self):
        if os.path.exists(ALERTS_FILE):
            try:
                with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                    self.alerts_history = json.load(f)
            except Exception:
                self.alerts_history = []
        else:
            self.alerts_history = []

    def _save_history(self):
        try:
            with open(ALERTS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.alerts_history[-200:], f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _load_whitelist(self):
        if os.path.exists(WHITELIST_FILE):
            try:
                with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
                    return set(x.lower() for x in json.load(f))
            except Exception:
                return set()
        return set()

    def _save_whitelist(self):
        try:
            with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
                json.dump(sorted(list(self.whitelist)), f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def add_to_whitelist(self, name: str):
        self.whitelist.add(name.lower().strip())
        self._save_whitelist()

    def remove_from_whitelist(self, name: str):
        self.whitelist.discard(name.lower().strip())
        self._save_whitelist()

    def get_whitelist(self):
        return sorted(list(self.whitelist))

    def get_startup_items(self):
        items = []
        startup_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        for hive, path in startup_paths:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        items.append({
                            "name": name,
                            "command": str(value),
                            "location": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                        })
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                continue
        return items

    def start(self):
        self.running = True
        while self.running:
            self.update()
            time.sleep(2)

    def stop(self):
        self.running = False

    def _collect_connections(self, pid_to_name: dict):
        connections = []
        private_prefixes = (
            "10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.",
            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
            "172.29.", "172.30.", "172.31.", "::1", "fe80:",
        )
        risky_ports = {4444, 5555, 6666, 31337, 12345, 3389, 445, 135, 22, 23}
        raw = []

        try:
            if hasattr(psutil, "net_connections"):
                raw = list(psutil.net_connections(kind="inet"))
            else:
                raw = list(psutil.connections(kind="inet"))
        except Exception:
            raw = []

        if not raw:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    if hasattr(proc, "net_connections"):
                        raw.extend(proc.net_connections(kind="inet"))
                    else:
                        raw.extend(proc.connections(kind="inet"))
                except Exception:
                    continue

        for conn in raw:
            try:
                status = getattr(conn, "status", None) or "UNKNOWN"
                if status == "NONE":
                    continue

                laddr = "—"
                if conn.laddr:
                    if hasattr(conn.laddr, "ip"):
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                    else:
                        laddr = f"{conn.laddr[0]}:{conn.laddr[1]}"

                raddr = "—"
                remote_ip = ""
                remote_port = 0
                if conn.raddr:
                    if hasattr(conn.raddr, "ip"):
                        remote_ip = str(conn.raddr.ip)
                        remote_port = int(conn.raddr.port)
                        raddr = f"{remote_ip}:{remote_port}"
                    else:
                        remote_ip = str(conn.raddr[0])
                        remote_port = int(conn.raddr[1])
                        raddr = f"{remote_ip}:{remote_port}"

                pid = conn.pid or 0
                proc_name = pid_to_name.get(pid, "Unknown")
                if proc_name == "Unknown" and pid:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except Exception:
                        proc_name = f"PID:{pid}"

                is_sus_conn = False
                sus_reason = ""

                if remote_ip and not any(remote_ip.startswith(p) for p in private_prefixes):
                    if remote_port in risky_ports:
                        is_sus_conn = True
                        sus_reason = f"Рисковый порт {remote_port}"

                proc_lower = proc_name.lower()
                for kw in ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "certutil"):
                    if kw in proc_lower and remote_ip and not any(remote_ip.startswith(p) for p in private_prefixes):
                        is_sus_conn = True
                        sus_reason = f"Подозрительный процесс в сети: {kw}"
                        break

                connections.append({
                    "pid": pid,
                    "process": proc_name,
                    "local": laddr,
                    "remote": raddr,
                    "status": status,
                    "is_suspicious": is_sus_conn,
                    "reason": sus_reason,
                })
            except Exception:
                continue

        connections.sort(
            key=lambda x: (
                not x.get("is_suspicious", False),
                x["status"] != "ESTABLISHED",
                x["process"],
            )
        )
        return connections

    def update(self):
        processes = []
        alerts = []
        pid_to_name = {}

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                info = proc.as_dict(attrs=["pid", "name"])
                name = info.get("name") or "Unknown"
                name_lower = name.lower()
                pid = info["pid"]
                pid_to_name[pid] = name

                cpu = round(proc.cpu_percent(interval=None), 1)
                mem = round(proc.memory_percent(), 1)

                try:
                    exe_path = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe_path = "—"

                path_lower = exe_path.lower() if exe_path != "—" else ""

                is_suspicious = False
                reason = ""

                if name_lower in self.whitelist:
                    is_suspicious = False
                    reason = ""
                else:
                    for kw in self.suspicious_keywords:
                        if kw in name_lower:
                            is_suspicious = True
                            reason = f"Подозрительное имя: {kw}"
                            break

                    if not is_suspicious and path_lower:
                        for sp in self.suspicious_paths:
                            if sp in path_lower:
                                is_suspicious = True
                                reason = "Запущен из подозрительной папки"
                                break

                    if not is_suspicious:
                        if cpu > 90:
                            is_suspicious = True
                            reason = "Очень высокая нагрузка CPU"
                        elif mem > 75:
                            is_suspicious = True
                            reason = "Высокое потребление памяти"
                        elif cpu > 50 and mem > 40:
                            is_suspicious = True
                            reason = "Высокая нагрузка CPU + Memory"

                    if any(safe in name_lower for safe in self.safe_processes):
                        is_suspicious = False
                        reason = ""

                processes.append({
                    "pid": pid,
                    "name": name,
                    "cpu": cpu,
                    "memory": mem,
                    "path": exe_path,
                    "is_suspicious": is_suspicious,
                    "reason": reason,
                })

                if is_suspicious:
                    alert_key = f"{name}|{reason}"
                    if alert_key not in self.seen_alerts:
                        self.seen_alerts.add(alert_key)
                        alert = {
                            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "message": f"{name} — {reason}",
                        }
                        alerts.append(alert)
                        self.alerts_history.insert(0, alert)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if len(self.seen_alerts) > 100:
            self.seen_alerts.clear()

        processes.sort(key=lambda x: x["cpu"], reverse=True)
        connections = self._collect_connections(pid_to_name)

        with self.lock:
            self.processes = processes[:150]
            self.connections = connections[:300]
            self.system_info = {
                "cpu": psutil.cpu_percent(interval=0.3),
                "memory": psutil.virtual_memory().percent,
                "disk": psutil.disk_usage("C:\\").percent if os.name == "nt" else psutil.disk_usage("/").percent,
            }
            self.alerts = (alerts + self.alerts)[:15]
            self.alerts_history = self.alerts_history[:200]
            self._save_history()

    def get_data(self):
        with self.lock:
            return {
                "processes": self.processes.copy(),
                "connections": self.connections.copy(),
                "system": self.system_info.copy(),
                "alerts": self.alerts.copy(),
                "alerts_history": self.alerts_history.copy(),
                "whitelist": self.get_whitelist(),
                "startup": self.get_startup_items(),
            }

    def clear_history(self):
        with self.lock:
            self.alerts_history = []
            self._save_history()

    def kill_process(self, pid: int) -> bool:
        try:
            p = psutil.Process(pid)
            p.terminate()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            try:
                p = psutil.Process(pid)
                p.kill()
                return True
            except Exception:
                return False