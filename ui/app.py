import flet as ft
import asyncio
import sys
import os
import json
import winreg
import threading
from datetime import datetime
from core.ai_assistant import AIAssistant

APP_NAME = "EDR.D"


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
    except Exception:
        return False


def set_autostart(enable: bool):
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        0, winreg.KEY_SET_VALUE
    )
    try:
        if enable:
            if getattr(sys, "frozen", False):
                value = f'"{sys.executable}"'
            else:
                main_path = os.path.abspath("main.py")
                value = f'"{sys.executable}" "{main_path}"'
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, value)
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass
    finally:
        winreg.CloseKey(key)


class MiniEDRApp:
    def __init__(self, page: ft.Page, monitor):
        self.page = page
        self.page.window.icon = "icon.ico"
        self.monitor = monitor
        self.current_tab = "overview"
        self.search_term = ""
        self.net_search = ""
        self.expanded_groups = set()
        self.expanded_net_groups = set()

        self.page.title = "EDR.D"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.padding = 0
        self.page.bgcolor = "#0f0f0f"

        self.ai = AIAssistant()
        self.ai_result = ft.Text(
            "Нажми «Сводка сессии» или иконку AI у процесса/алерта.",
            size=13, color="#e5e7eb", selectable=True
        )
        self.ai_status = ft.Text(
            "AI: готов" if self.ai.available else "AI: модель не найдена",
            size=12,
            color="#4ade80" if self.ai.available else "#f87171"
        )

        self.cpu_text = ft.Text("0%", size=36, weight=ft.FontWeight.BOLD)
        self.memory_text = ft.Text("0%", size=36, weight=ft.FontWeight.BOLD)
        self.disk_text = ft.Text("0%", size=36, weight=ft.FontWeight.BOLD)

        self.alerts_column = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO, height=180)
        self.history_list = ft.ListView(expand=True, spacing=4, padding=10)
        self.whitelist_list = ft.Column(spacing=4)
        self.startup_list = ft.ListView(expand=True, spacing=0, padding=10)
        self.processes_list = ft.ListView(expand=True, spacing=0, padding=10)
        self.connections_list = ft.ListView(expand=True, spacing=0, padding=10)

        self.search_field = ft.TextField(
            hint_text="Поиск процесса...",
            prefix_icon=ft.Icons.SEARCH,
            border_radius=10, bgcolor="#1a1a1a", border_color="#333333",
            focused_border_color="#3b82f6", on_change=self.on_search_change,
            width=280, height=42
        )
        self.net_search_field = ft.TextField(
            hint_text="Поиск по IP / процессу...",
            prefix_icon=ft.Icons.SEARCH,
            border_radius=10, bgcolor="#1a1a1a", border_color="#333333",
            focused_border_color="#3b82f6", on_change=self.on_net_search_change,
            width=280, height=42
        )
        self.whitelist_input = ft.TextField(
            hint_text="Имя процесса (например chrome.exe)",
            border_radius=10, bgcolor="#1a1a1a", border_color="#333333",
            focused_border_color="#3b82f6", width=280, height=42
        )

        self.content_area = ft.Container(expand=True, padding=20)
        self.status_text = ft.Text("", color="#4ade80", size=13)

        self.autostart_switch = ft.Switch(
            label="Запускать вместе с Windows",
            value=is_autostart_enabled(),
            on_change=self.on_autostart_change,
            active_color="#22c55e"
        )
        self.autostart_status = ft.Text(
            "Включено" if is_autostart_enabled() else "Выключено",
            color="#4ade80" if is_autostart_enabled() else "#9ca3af",
            size=13
        )

    def on_search_change(self, e):
        self.search_term = e.control.value.lower().strip()

    def on_net_search_change(self, e):
        self.net_search = e.control.value.lower().strip()

    def on_autostart_change(self, e):
        enabled = e.control.value
        try:
            set_autostart(enabled)
            self.autostart_status.value = "Включено" if enabled else "Выключено"
            self.autostart_status.color = "#4ade80" if enabled else "#9ca3af"
            self.status_text.value = "Автозапуск обновлён"
            self.status_text.color = "#4ade80"
        except Exception as ex:
            self.status_text.value = f"Ошибка автозапуска: {ex}"
            self.status_text.color = "#f87171"
            self.autostart_switch.value = not enabled
        self.page.update()

    def add_whitelist(self, e):
        name = self.whitelist_input.value.strip()
        if name:
            self.monitor.add_to_whitelist(name)
            self.whitelist_input.value = ""
            self.status_text.value = f"Добавлено в белый список: {name}"
            self.status_text.color = "#4ade80"
            self._refresh_whitelist()
            self.page.update()

    def remove_whitelist(self, name):
        self.monitor.remove_from_whitelist(name)
        self.status_text.value = f"Удалено из белого списка: {name}"
        self.status_text.color = "#f87171"
        self._refresh_whitelist()
        self.page.update()

    def _refresh_whitelist(self):
        items = self.monitor.get_whitelist()
        if not items:
            self.whitelist_list.controls = [ft.Text("Белый список пуст", color="#6b7280", size=13)]
        else:
            self.whitelist_list.controls = [
                ft.Container(
                    content=ft.Row([
                        ft.Text(name, size=13, expand=True),
                        ft.IconButton(
                            icon=ft.Icons.CLOSE, icon_color="#f87171", icon_size=16,
                            tooltip="Удалить",
                            on_click=lambda e, n=name: self.remove_whitelist(n)
                        )
                    ]),
                    padding=8,
                    border=ft.Border(bottom=ft.BorderSide(1, "#2a2a2a")),
                )
                for name in items
            ]

    def export_history(self, e):
        data = self.monitor.get_data()
        history = data.get("alerts_history", [])
        if not history:
            self.status_text.value = "Нечего экспортировать — история пуста"
            self.status_text.color = "#f87171"
            self.page.update()
            return
        filename = f"alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(history, f, ensure_ascii=False, indent=2)
            self.status_text.value = f"История сохранена: {filename}"
            self.status_text.color = "#4ade80"
        except Exception as ex:
            self.status_text.value = f"Ошибка экспорта: {ex}"
            self.status_text.color = "#f87171"
        self.page.update()

    def _run_ai(self, func, *args):
        self.ai_status.value = "AI: думает..."
        self.ai_status.color = "#fbbf24"
        self.ai_result.value = "Анализирую, подожди..."
        self.page.update()

        def worker():
            try:
                result = func(*args)
            except Exception as e:
                result = f"Ошибка: {e}"
            self.ai_result.value = result
            self.ai_status.value = "AI: готов" if self.ai.available else "AI: Ollama не найдена"
            self.ai_status.color = "#4ade80" if self.ai.available else "#f87171"
            self.page.update()

        threading.Thread(target=worker, daemon=True).start()

    def ask_ai_summary(self, e):
        data = self.monitor.get_data()
        self._run_ai(
            self.ai.summarize_session,
            data.get("alerts_history", [])[:10],
            len(data.get("processes", [])),
            len(data.get("connections", []))
        )

    def ask_ai_alert(self, message: str):
        self.current_tab = "overview"
        self.update_content()
        self._run_ai(self.ai.explain_alert, message)
        self.page.update()

    def ask_ai_process(self, name: str, path: str, cpu: float, memory: float, reason: str = ""):
        self.current_tab = "overview"
        self.update_content()
        self._run_ai(self.ai.analyze_process, name, path, cpu, memory, reason)
        self.page.update()

    def change_tab(self, tab_name: str):
        self.current_tab = tab_name
        self.update_content()
        self.page.update()

    def toggle_group(self, name: str):
        if name in self.expanded_groups:
            self.expanded_groups.remove(name)
        else:
            self.expanded_groups.add(name)
        self.page.update()

    def toggle_net_group(self, name: str):
        if name in self.expanded_net_groups:
            self.expanded_net_groups.remove(name)
        else:
            self.expanded_net_groups.add(name)
        self.page.update()

    def kill_process(self, pid: int, name: str):
        success = self.monitor.kill_process(pid)
        if success:
            self.status_text.value = f"Процесс {name} (PID {pid}) завершён"
            self.status_text.color = "#4ade80"
        else:
            self.status_text.value = f"Не удалось завершить {name}"
            self.status_text.color = "#f87171"
        self.page.update()

    def clear_history(self, e):
        self.monitor.clear_history()
        self.history_list.controls = [ft.Text("История очищена", color="#6b7280", size=14)]
        self.page.update()

    def build(self):
        self.sidebar = ft.Container(
            width=210, bgcolor="#141414", padding=20,
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.SECURITY, color="#22c55e", size=28),
                    ft.Text("EDR.D", size=22, weight=ft.FontWeight.BOLD)
                ], spacing=10),
                ft.Divider(height=25, color="#333333"),
                self._nav_button("Обзор", "overview", ft.Icons.DASHBOARD),
                self._nav_button("Процессы", "processes", ft.Icons.LIST_ALT),
                self._nav_button("Сеть", "network", ft.Icons.LAN),
                self._nav_button("Автозагрузка", "startup", ft.Icons.ROCKET_LAUNCH),
                self._nav_button("История", "history", ft.Icons.HISTORY),
                self._nav_button("Настройки", "settings", ft.Icons.SETTINGS),
                ft.Container(expand=True),
                self.ai_status,
                ft.Text("v1.0", color="#555555", size=12)
            ], expand=True)
        )
        self.page.add(
            ft.Row(controls=[self.sidebar, self.content_area], expand=True, spacing=0)
        )
        self.update_content()
        self.page.run_task(self.update_ui)

    def _nav_button(self, text, tab_name, icon):
        return ft.Container(
            content=ft.Row([ft.Icon(icon, size=20), ft.Text(text, size=15)], spacing=12),
            padding=12, border_radius=8,
            on_click=lambda e: self.change_tab(tab_name),
            ink=True,
        )

    def update_content(self):
        if self.current_tab == "overview":
            self.content_area.content = self._build_overview()
        elif self.current_tab == "processes":
            self.content_area.content = self._build_processes()
        elif self.current_tab == "network":
            self.content_area.content = self._build_network()
        elif self.current_tab == "startup":
            self.content_area.content = self._build_startup()
        elif self.current_tab == "history":
            self.content_area.content = self._build_history()
        elif self.current_tab == "settings":
            self.content_area.content = self._build_settings()
            self._refresh_whitelist()

    def _build_overview(self):
        system_cards = ft.Row([
            self._create_card("CPU", self.cpu_text),
            self._create_card("Память", self.memory_text),
            self._create_card("Диск", self.disk_text),
        ], spacing=15)

        alerts_box = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.WARNING_AMBER, color="#ef4444", size=22),
                    ft.Text("Подозрительная активность", weight=ft.FontWeight.BOLD, color="#f87171", size=16)
                ], spacing=8),
                self.alerts_column
            ]),
            bgcolor="#1f1215",
            border=ft.Border(
                left=ft.BorderSide(1, "#7f1d1d"), top=ft.BorderSide(1, "#7f1d1d"),
                right=ft.BorderSide(1, "#7f1d1d"), bottom=ft.BorderSide(1, "#7f1d1d"),
            ),
            border_radius=12, padding=18,
        )

        ai_box = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.PSYCHOLOGY, color="#a78bfa", size=22),
                    ft.Text("AI-ассистент (локальная модель)", weight=ft.FontWeight.BOLD, size=16),
                ], spacing=10),
                ft.Container(height=6),
                self.ai_status,
                ft.Container(height=10),
                ft.ElevatedButton(
                    "Сводка сессии", icon=ft.Icons.AUTO_AWESOME,
                    on_click=self.ask_ai_summary, bgcolor="#5b21b6", color="white",
                ),
                ft.Container(height=10),
                ft.Container(content=self.ai_result, bgcolor="#121212", border_radius=8, padding=12),
            ]),
            bgcolor="#1a1a1a", border_radius=12, padding=18,
        )

        return ft.Column([
            ft.Text("Обзор системы", size=26, weight=ft.FontWeight.BOLD),
            ft.Container(height=15), system_cards,
            ft.Container(height=20), alerts_box,
            ft.Container(height=15), ai_box,
        ], scroll=ft.ScrollMode.AUTO, expand=True)

    def _build_processes(self):
        header = ft.Row([
            ft.Text("Активные процессы", size=24, weight=ft.FontWeight.BOLD),
            self.search_field
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)

        columns_header = ft.Container(
            content=ft.Row([
                ft.Container(width=28),
                ft.Text("Процесс", width=180, weight=ft.FontWeight.BOLD, size=13),
                ft.Text("Кол-во", width=55, weight=ft.FontWeight.BOLD, size=13),
                ft.Text("CPU %", width=65, weight=ft.FontWeight.BOLD, size=13),
                ft.Text("Память %", width=75, weight=ft.FontWeight.BOLD, size=13),
                ft.Text("Статус", width=100, weight=ft.FontWeight.BOLD, size=13),
                ft.Text("AI", width=36, weight=ft.FontWeight.BOLD, size=13),
            ]),
            padding=10, bgcolor="#222222", border_radius=10,
        )

        table_container = ft.Container(
            content=ft.Column([columns_header, self.processes_list], expand=True, spacing=0),
            bgcolor="#1a1a1a", border_radius=12, expand=True, padding=10,
        )
        return ft.Column([
            header, ft.Container(height=8), self.status_text,
            ft.Container(height=8), table_container
        ], expand=True)

    def _build_network(self):
        header = ft.Row([
            ft.Text("Сетевые соединения", size=24, weight=ft.FontWeight.BOLD),
            self.net_search_field
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)

        columns_header = ft.Container(
            content=ft.Row([
                ft.Container(width=28),
                ft.Text("Процесс", width=180, weight=ft.FontWeight.BOLD, size=13),
                ft.Text("Кол-во", width=60, weight=ft.FontWeight.BOLD, size=13),
                ft.Text("Пример адреса", expand=True, weight=ft.FontWeight.BOLD, size=13),
            ]),
            padding=10, bgcolor="#222222", border_radius=10,
        )

        table_container = ft.Container(
            content=ft.Column([columns_header, self.connections_list], expand=True, spacing=0),
            bgcolor="#1a1a1a", border_radius=12, expand=True, padding=10,
        )
        return ft.Column([header, ft.Container(height=12), table_container], expand=True)

    def _build_startup(self):
        columns_header = ft.Container(
            content=ft.Row([
                ft.Text("Имя", width=200, weight=ft.FontWeight.BOLD, size=13),
                ft.Text("Расположение", width=80, weight=ft.FontWeight.BOLD, size=13),
                ft.Text("Команда", expand=True, weight=ft.FontWeight.BOLD, size=13),
            ]),
            padding=10, bgcolor="#222222", border_radius=10,
        )
        return ft.Column([
            ft.Text("Автозагрузка Windows", size=24, weight=ft.FontWeight.BOLD),
            ft.Container(height=8),
            ft.Text("Программы при входе в систему", color="#9ca3af", size=13),
            ft.Container(height=15),
            ft.Container(
                content=ft.Column([columns_header, self.startup_list], expand=True, spacing=0),
                bgcolor="#1a1a1a", border_radius=12, expand=True, padding=10,
            )
        ], expand=True)

    def _build_history(self):
        header = ft.Row([
            ft.Text("История алертов", size=24, weight=ft.FontWeight.BOLD),
            ft.Row([
                ft.ElevatedButton("Экспорт", icon=ft.Icons.DOWNLOAD, on_click=self.export_history,
                                  bgcolor="#1d4ed8", color="white"),
                ft.ElevatedButton("Очистить", icon=ft.Icons.DELETE_OUTLINE, on_click=self.clear_history,
                                  bgcolor="#7f1d1d", color="white"),
            ], spacing=10)
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)

        return ft.Column([
            header, ft.Container(height=8), self.status_text, ft.Container(height=8),
            ft.Container(content=self.history_list, bgcolor="#1a1a1a", border_radius=12,
                         expand=True, padding=15),
        ], expand=True)

    def _build_settings(self):
        return ft.Column([
            ft.Text("Настройки", size=26, weight=ft.FontWeight.BOLD),
            ft.Container(height=20),
            ft.Container(
                content=ft.Column([
                    ft.Text("Автозапуск", size=18, weight=ft.FontWeight.BOLD),
                    ft.Container(height=10),
                    ft.Row([self.autostart_switch, self.autostart_status], spacing=15),
                    ft.Text("Запуск при входе в Windows", color="#6b7280", size=13),
                ]),
                bgcolor="#1a1a1a", border_radius=12, padding=20,
            ),
            ft.Container(height=15),
            ft.Container(
                content=ft.Column([
                    ft.Text("Белый список", size=18, weight=ft.FontWeight.BOLD),
                    ft.Container(height=6),
                    ft.Text("Эти процессы не считаются подозрительными", color="#6b7280", size=13),
                    ft.Container(height=12),
                    ft.Row([
                        self.whitelist_input,
                        ft.ElevatedButton("Добавить", icon=ft.Icons.ADD, on_click=self.add_whitelist,
                                          bgcolor="#166534", color="white"),
                    ], spacing=10),
                    ft.Container(height=12),
                    self.whitelist_list,
                ]),
                bgcolor="#1a1a1a", border_radius=12, padding=20,
            ),
            ft.Container(height=15),
            ft.Container(
                content=ft.Column([
                    ft.Text("О программе", size=18, weight=ft.FontWeight.BOLD),
                    ft.Container(height=8),
                    ft.Text("EDR.D v1.0 + Local AI", size=14),
                    ft.Text("Мониторинг процессов, сети и AI-анализ", color="#9ca3af", size=13),
                ]),
                bgcolor="#1a1a1a", border_radius=12, padding=20,
            ),
        ], scroll=ft.ScrollMode.AUTO, expand=True)

    def _create_card(self, title, value_text):
        return ft.Container(
            content=ft.Column([
                ft.Text(title, color="#9ca3af", size=14),
                value_text
            ], spacing=8),
            bgcolor="#1a1a1a", border_radius=12, padding=22, expand=True,
            border=ft.Border(
                left=ft.BorderSide(1, "#333333"), top=ft.BorderSide(1, "#333333"),
                right=ft.BorderSide(1, "#333333"), bottom=ft.BorderSide(1, "#333333"),
            )
        )

    def _group_processes(self, processes):
        groups = {}
        for p in processes:
            name = p["name"]
            if name not in groups:
                groups[name] = {
                    "name": name, "count": 0, "cpu": 0.0, "memory": 0.0,
                    "is_suspicious": False, "items": []
                }
            groups[name]["count"] += 1
            groups[name]["cpu"] += p["cpu"]
            groups[name]["memory"] += p["memory"]
            if p["is_suspicious"]:
                groups[name]["is_suspicious"] = True
            groups[name]["items"].append(p)
        result = list(groups.values())
        result.sort(key=lambda x: x["cpu"], reverse=True)
        return result

    def _group_connections(self, connections):
        groups = {}
        for c in connections:
            name = c.get("process") or "Unknown"
            if name not in groups:
                groups[name] = {
                    "name": name,
                    "count": 0,
                    "example": c["remote"] if c.get("remote") and c["remote"] != "—" else c.get("local", "—"),
                    "items": []
                }
            groups[name]["count"] += 1
            groups[name]["items"].append(c)
        result = list(groups.values())
        result.sort(key=lambda x: x["count"], reverse=True)
        return result

    def _create_group_row(self, group):
        is_expanded = group["name"] in self.expanded_groups
        icon = ft.Icons.EXPAND_MORE if is_expanded else ft.Icons.CHEVRON_RIGHT
        status = "Подозрительно" if group["is_suspicious"] else "Нормально"
        status_color = "#f87171" if group["is_suspicious"] else "#4ade80"

        first = group["items"][0] if group["items"] else {}
        path = first.get("path", "—")
        reason = first.get("reason", "")

        ai_btn = ft.IconButton(
            icon=ft.Icons.PSYCHOLOGY, icon_color="#a78bfa", icon_size=16,
            tooltip="AI-анализ процесса",
            on_click=lambda e, n=group["name"], p=path, c=group["cpu"], m=group["memory"], r=reason:
                self.ask_ai_process(n, p, c, m, r),
        )

        main_row = ft.Container(
            content=ft.Row([
                ft.IconButton(
                    icon=icon, icon_size=18, icon_color="#9ca3af",
                    on_click=lambda e, n=group["name"]: self.toggle_group(n),
                    style=ft.ButtonStyle(padding=0)
                ),
                ft.Text(group["name"], width=180, size=13, weight=ft.FontWeight.W_500),
                ft.Text(str(group["count"]), width=55, size=13, color="#9ca3af"),
                ft.Text(f"{round(group['cpu'], 1)}%", width=65, size=13),
                ft.Text(f"{round(group['memory'], 1)}%", width=75, size=13),
                ft.Text(status, width=100, size=13, color=status_color),
                ai_btn,
            ]),
            padding=6,
            bgcolor="#1f1f1f" if is_expanded else None,
            border=ft.Border(bottom=ft.BorderSide(1, "#2a2a2a")),
        )

        rows = [main_row]
        if is_expanded:
            for p in group["items"]:
                kill_btn = ft.IconButton(
                    icon=ft.Icons.CLOSE, icon_color="#f87171", icon_size=15,
                    tooltip="Завершить",
                    on_click=lambda e, pid=p["pid"], name=p["name"]: self.kill_process(pid, name),
                )
                child = ft.Container(
                    content=ft.Row([
                        ft.Container(width=28),
                        ft.Text(f"└─ PID {p['pid']}", width=180, size=12, color="#9ca3af"),
                        ft.Text("1", width=55, size=12, color="#6b7280"),
                        ft.Text(f"{p['cpu']}%", width=65, size=12),
                        ft.Text(f"{p['memory']}%", width=75, size=12),
                        ft.Text("", width=100),
                        kill_btn,
                    ]),
                    padding=4, bgcolor="#161616",
                    border=ft.Border(bottom=ft.BorderSide(1, "#222222")),
                )
                rows.append(child)
        return ft.Column(rows, spacing=0)

    def _create_net_group_row(self, group):
        is_expanded = group["name"] in self.expanded_net_groups
        icon = ft.Icons.EXPAND_MORE if is_expanded else ft.Icons.CHEVRON_RIGHT
        group_suspicious = any(c.get("is_suspicious") for c in group["items"])
        name_color = "#f87171" if group_suspicious else None

        main_row = ft.Container(
            content=ft.Row([
                ft.IconButton(
                    icon=icon, icon_size=18, icon_color="#9ca3af",
                    on_click=lambda e, n=group["name"]: self.toggle_net_group(n),
                    style=ft.ButtonStyle(padding=0)
                ),
                ft.Text(group["name"], width=180, size=13, weight=ft.FontWeight.W_500, color=name_color),
                ft.Text(str(group["count"]), width=60, size=13, color="#9ca3af"),
                ft.Text(
                    group["example"], expand=True, size=12,
                    color="#f87171" if group_suspicious else "#9ca3af"
                ),
            ]),
            padding=6,
            bgcolor="#1f1215" if group_suspicious else ("#1f1f1f" if is_expanded else None),
            border=ft.Border(bottom=ft.BorderSide(1, "#2a2a2a")),
            on_click=lambda e, n=group["name"]: self.toggle_net_group(n),
        )

        rows = [main_row]
        if is_expanded:
            for c in group["items"]:
                sus = c.get("is_suspicious", False)
                text_color = "#f87171" if sus else "#6b7280"
                reason = c.get("reason", "")
                extra = f"  ⚠ {reason}" if sus and reason else ""
                child = ft.Container(
                    content=ft.Row([
                        ft.Container(width=28),
                        ft.Text(f"└─ {c['local']}", width=180, size=12, color="#9ca3af"),
                        ft.Text("", width=60),
                        ft.Text(
                            f"{c['remote']}  [{c['status']}]{extra}",
                            expand=True, size=12, color=text_color
                        ),
                    ]),
                    padding=4,
                    bgcolor="#1a0a0a" if sus else "#161616",
                    border=ft.Border(bottom=ft.BorderSide(1, "#222222")),
                )
                rows.append(child)
        return ft.Column(rows, spacing=0)

    def _create_startup_row(self, item):
        cmd = item.get("command", "—")
        if len(cmd) > 80:
            cmd = cmd[:77] + "..."
        return ft.Container(
            content=ft.Row([
                ft.Text(item.get("name", "—"), width=200, size=13, no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS),
                ft.Text(item.get("location", "—"), width=80, size=13, color="#9ca3af"),
                ft.Text(cmd, expand=True, size=12, color="#9ca3af", no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS),
            ]),
            padding=8,
            border=ft.Border(bottom=ft.BorderSide(1, "#2a2a2a")),
        )

    async def update_ui(self):
        while True:
            data = self.monitor.get_data()

            self.cpu_text.value = f"{data['system']['cpu']}%"
            self.memory_text.value = f"{data['system']['memory']}%"
            self.disk_text.value = f"{data['system']['disk']}%"

            if data["alerts"]:
                self.alerts_column.controls = [
                    ft.Text(f"{a['time']} — {a['message']}", color="#fca5a5", size=13)
                    for a in data["alerts"][:8]
                ]
            else:
                self.alerts_column.controls = [
                    ft.Text("Подозрительная активность не обнаружена", color="#6b7280", size=13)
                ]

            history = data.get("alerts_history", [])
            if history:
                self.history_list.controls = [
                    ft.Container(
                        content=ft.Row([
                            ft.Text(f"{a['time']}  —  {a['message']}", color="#fca5a5", size=13, expand=True),
                            ft.IconButton(
                                icon=ft.Icons.PSYCHOLOGY, icon_color="#a78bfa", icon_size=18,
                                tooltip="Объяснить через AI",
                                on_click=lambda e, msg=a["message"]: self.ask_ai_alert(msg),
                            ),
                        ]),
                        padding=8,
                        border=ft.Border(bottom=ft.BorderSide(1, "#2a2a2a")),
                    )
                    for a in history[:100]
                ]
            else:
                self.history_list.controls = [ft.Text("История пуста", color="#6b7280", size=14)]

            startup = data.get("startup", [])
            if startup:
                self.startup_list.controls = [self._create_startup_row(s) for s in startup]
            else:
                self.startup_list.controls = [
                    ft.Text("Нет данных или нет доступа к реестру", color="#6b7280", size=13)
                ]

            filtered = data["processes"]
            if self.search_term:
                filtered = [p for p in filtered if self.search_term in p["name"].lower()]
            groups = self._group_processes(filtered)
            self.processes_list.controls = [self._create_group_row(g) for g in groups[:60]]

            net_filtered = data.get("connections", [])
            if self.net_search:
                net_filtered = [
                    c for c in net_filtered
                    if self.net_search in c.get("process", "").lower()
                    or self.net_search in c.get("local", "").lower()
                    or self.net_search in c.get("remote", "").lower()
                ]
            net_groups = self._group_connections(net_filtered)
            self.connections_list.controls = [self._create_net_group_row(g) for g in net_groups[:50]]

            self.page.update()
            await asyncio.sleep(2)