"""系统托盘常驻程序。

用 pystray 做 Windows 任务栏图标，后台跑 DashboardServer（抓包+HTTP+轮询）。
右键菜单：打开面板 / 状态 / 退出。图标颜色按告警状态自动变化。
"""
from __future__ import annotations

import threading
import time
import webbrowser

from core import dashboard as dash_mod


def _make_icon(color: str) -> "PIL.Image.Image":
    """生成 64x64 纯色圆形图标。color: 'green' | 'yellow' | 'red'."""
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse((4, 4, 60, 60), fill=color)
    return img


class TrayApp:
    def __init__(self, iface: str | None = None, port: int = 9876,
                 csv_path: str | None = None, json_path: str | None = None):
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.dashboard = dash_mod.DashboardServer(
            port=port, iface=iface, csv_path=csv_path, json_path=json_path,
            auto_open=True,  # 双击 exe 自动打开浏览器面板
        )
        self._icon = None
        self._stop = threading.Event()

    def _build_menu(self):
        import pystray
        return pystray.Menu(
            pystray.MenuItem("打开面板", self._open_dashboard, default=True),
            pystray.MenuItem(f"状态: 启动中...", self._noop, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出监控", self._quit),
        )

    def _noop(self):
        pass

    def _open_dashboard(self):
        webbrowser.open(self.url)

    def _quit(self):
        self._stop.set()
        if self._icon:
            self._icon.stop()

    def _status_updater(self):
        """后台线程：按告警状态更新托盘图标颜色和状态文字."""
        colors = ["green", "yellow", "red"]
        last_color = "green"
        last_text = "状态: 正常"
        while not self._stop.is_set():
            time.sleep(3)
            try:
                state = self.dashboard.state
                new_color = last_color
                new_text = last_text
                if state.alert_count > 0:
                    new_color = "red"
                    new_text = f"状态: {state.alert_count} 个告警"
                elif any(d["is_agent"] for d in state.domains.values()):
                    new_color = "yellow"
                    new_text = f"状态: {len(state.domains)} 个域名监控中"
                else:
                    new_color = "green"
                    new_text = f"状态: 正常 ({len(state.domains)} 域名)"
                if new_color != last_color and self._icon:
                    self._icon.icon = _make_icon(new_color)
                    # 更新菜单状态行（pystray 不支持动态更新 MenuItem 文字，用 title）
                    self._icon.title = f"Agent Egress Monitor - {new_text}"
                last_color = new_color
            except Exception:
                pass

    def run(self):
        self.dashboard.start()
        # HTTP 服务在后台线程
        threading.Thread(target=self.dashboard.serve, daemon=True).start()
        # 状态更新线程
        threading.Thread(target=self._status_updater, daemon=True).start()

        import pystray
        self._icon = pystray.Icon(
            "agentmon",
            _make_icon("green"),
            "Agent Egress Monitor",
            menu=self._build_menu(),
        )
        self._icon.run()
        self.dashboard.stop()
