"""进程归属：把抓到的出向流量归因到具体进程（Windows）。

抓包本身只能看到「本地端口 + 远端」。要回答「这条流量是哪个程序发的」，
需要在 OS 层把 本地端口 -> PID -> 进程名 建立映射。

用 psutil 纯 Python 实现（不调 PowerShell），避免触发 360 等安全软件的
"Python→PowerShell→注册表" 误报链。

非 Windows / 权限不足时自动降级（available=False），不影响抓包。
"""
from __future__ import annotations

import os as _os
import threading
import time


class ProcAttr:
    def __init__(self, refresh: float = 2.0):
        self.refresh = refresh
        self._map: dict[int, str] = {}
        self._lock = threading.Lock()
        self._last = 0.0
        self.available = False
        self._thread: threading.Thread | None = None

    def _query(self) -> None:
        try:
            import psutil
            m: dict[int, str] = {}
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status != "ESTABLISHED" or not conn.laddr:
                    continue
                try:
                    proc = psutil.Process(conn.pid)
                    m[conn.laddr.port] = proc.name() or f"pid_{conn.pid}"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            with self._lock:
                self._map = m
                self.available = True
                self._last = time.time()
        except Exception:
            with self._lock:
                self.available = False

    def start(self) -> None:
        def loop() -> None:
            while True:
                self._query()
                time.sleep(self.refresh)

        self._query()
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def lookup(self, local_port: int) -> str | None:
        with self._lock:
            return self._map.get(int(local_port))
