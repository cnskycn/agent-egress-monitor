"""本地 Web 面板：后台抓包 + HTTP 服务，浏览器实时查看外联事件。
支持一键启停 MITM 代理。

架构：
  - CaptureMonitor + ProcAttr 在后台线程运行
  - http.server 在主线程提供：
    GET /          → Web UI HTML
    GET /api/events  → 最近事件的 JSON
    GET /api/stats   → 汇总统计 JSON
    GET /api/alerts  → 告警汇总 JSON
    GET /api/bodies  → MITM 拦截内容 JSON
    GET /api/mitm/status → MITM 状态 JSON
    POST /api/mitm/start → 启动 MITM
    POST /api/mitm/stop  → 停止 MITM
  - 事件用环形缓冲区保存最近 500 条
"""
from __future__ import annotations

import json
import os
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

from core import capture, procattr, rules, logger as logger_mod


def _resolve_agent_cmd(name: str) -> str | None:
    """将 Agent 简写名称解析为实际可执行路径。多盘符搜索。"""
    import shutil
    home = os.environ.get("USERPROFILE", os.path.expanduser("~"))
    # 多个可能的 AppData 路径（处理 C:/E: 盘符不一致）
    appdata_dirs = [
        os.path.join(home, "AppData", "Local"),
        os.environ.get("LOCALAPPDATA", ""),
    ]
    # 补充常见盘符
    for drive in "C D E F".split():
        d = f"{drive}:\\Users\\{os.path.basename(home)}\\AppData\\Local"
        if d not in appdata_dirs:
            appdata_dirs.append(d)

    def _try_paths(agent_dirs):
        for local in appdata_dirs:
            for sub in agent_dirs:
                p = os.path.join(local, sub)
                if os.path.exists(p):
                    return p
        return None

    name_lower = name.lower()
    if name_lower == "trae":
        return _try_paths(["Programs\\Trae\\Trae.exe", "Programs\\Trae CN\\Trae CN.exe"]) or "trae"
    if name_lower == "qoder":
        return _try_paths(["Programs\\Qoder\\Qoder.exe"]) or "qoder"
    if name_lower == "cursor":
        return _try_paths(["Programs\\Cursor\\Cursor.exe"]) or "cursor"
    if name_lower == "windsurf":
        return _try_paths(["Programs\\Windsurf\\Windsurf.exe"]) or "windsurf"

    # CLI 命令（已在 PATH 中）
    if shutil.which(name):
        return name
    return name if os.path.exists(name.strip('"')) else None


_UI_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui")
_MAX_EVENTS = 500


class DashboardState:
    def __init__(self):
        self.events: list[dict] = []  # 环形缓冲
        self.domains: dict[str, dict] = {}  # sni -> {proc, uplink, count, last_seen, is_agent}
        self.bodies: list[dict] = []  # MITM 拦截到的请求体
        self.alerts: dict[str, dict] = {}  # (proc|sni|level) -> {count, total_uplink, last_ts, ...}
        self.total_uplink: int = 0
        self.alert_count: int = 0
        self._lock = threading.Lock()

    def add_event(self, proc: str, sni: str, dst: str, uplink: int,
                  is_agent: bool, alert: str = "") -> None:
        ts = time.strftime("%H:%M:%S")
        ev = {
            "ts": ts, "epoch": time.time(), "proc": proc, "sni": sni,
            "dst": dst, "uplink": uplink, "is_agent": is_agent, "alert": alert,
        }
        with self._lock:
            self.events.append(ev)
            if len(self.events) > _MAX_EVENTS:
                self.events = self.events[-_MAX_EVENTS:]
            d = self.domains.setdefault(sni, {
                "proc": proc, "uplink": 0, "count": 0,
                "last_seen": ts, "is_agent": is_agent,
            })
            d["uplink"] += uplink
            d["count"] += 1
            d["last_seen"] = ts
            d["proc"] = proc
            self.total_uplink += uplink
            if alert:
                self.alert_count += 1
                akey = f"{proc}|{sni}|{alert}"
                if akey in self.alerts:
                    self.alerts[akey]["count"] += 1
                    self.alerts[akey]["total_uplink"] += uplink
                    self.alerts[akey]["last_ts"] = ts
                else:
                    self.alerts[akey] = {
                        "proc": proc, "sni": sni, "alert": alert,
                        "count": 1, "total_uplink": uplink,
                        "first_ts": ts, "last_ts": ts, "is_agent": is_agent,
                    }

    def record_body(self, method: str, host: str, url: str, body: str,
                     canary_hit: bool = False, fp_hit: bool = False) -> None:
        ts = time.strftime("%H:%M:%S")
        body_preview = body[:500] if body else ""
        entry = {
            "ts": ts, "epoch": time.time(), "method": method,
            "host": host, "url": url, "body": body_preview,
            "canary_hit": canary_hit, "fp_hit": fp_hit,
        }
        with self._lock:
            self.bodies.append(entry)
            if len(self.bodies) > _MAX_EVENTS:
                self.bodies = self.bodies[-_MAX_EVENTS:]
            if canary_hit or fp_hit:
                self.alert_count += 1

    def bodies_json(self) -> str:
        with self._lock:
            return json.dumps(list(reversed(self.bodies[-100:])), ensure_ascii=False)

    def alerts_json(self) -> str:
        with self._lock:
            items = sorted(self.alerts.values(), key=lambda x: x["count"], reverse=True)
            return json.dumps(items, ensure_ascii=False)

    def events_json(self, since: int = 0) -> str:
        with self._lock:
            data = [e for e in self.events if e["epoch"] > since]
        return json.dumps(data, ensure_ascii=False)

    def stats_json(self) -> str:
        with self._lock:
            top = sorted(self.domains.values(), key=lambda x: x["uplink"], reverse=True)[:20]
            # 加入工具归属
            domains_data = []
            for sni, info in sorted(
                self.domains.items(), key=lambda x: x[1]["uplink"], reverse=True
            )[:20]:
                entry = {"sni": sni, **info}
                entry["tool"] = rules.get_tool_for_domain(sni) if info.get("is_agent") else ""
                domains_data.append(entry)
            return json.dumps({
                "total_domains": len(self.domains),
                "total_uplink": self.total_uplink,
                "alert_count": self.alert_count,
                "event_count": len(self.events),
                "top_domains": domains_data,
                "running_agents": rules.detect_running_agents(),
            }, ensure_ascii=False)


class DashboardServer:
    def __init__(self, port: int = 9876, iface: str | None = None,
                 csv_path: str | None = None, json_path: str | None = None,
                 auto_open: bool = True):
        self.port = port
        self.iface = iface
        self.state = DashboardState()
        self.mon = capture.CaptureMonitor(iface=iface)
        self.pa = procattr.ProcAttr()
        self.logger = logger_mod.EgressLogger(csv_path, json_path) if (csv_path or json_path) else None
        self.auto_open = auto_open
        self._stop = threading.Event()
        self._poller: threading.Thread | None = None
        self._mitm_proxy = None
        self._mitm_running = False
        self._mitm_port = 8080
        self._agent_process = None
        self._agent_output: list[str] = []
        self._agent_lock = threading.Lock()

    def start(self) -> None:
        self.pa.start()
        self.mon.start()
        self._poller = threading.Thread(target=self._poll_loop, daemon=True)
        self._poller.start()

    def stop(self) -> None:
        self._stop.set()
        self.mon.stop()
        if self.logger:
            self.logger.close()

    def _poll_loop(self) -> None:
        reported: set = set()
        totals: dict = {}
        cfg = rules.Config()
        while not self._stop.is_set():
            time.sleep(1.5)
            cur: dict = {}
            for key, s in list(self.mon.stats.items()):
                if not s.tls_seen or not s.sni:
                    continue
                proc = self.pa.lookup(s.sport) if s.sport else None
                proc = proc or "(unknown)"
                k = (proc, s.sni)
                cur[k] = cur.get(k, 0) + s.uplink_bytes
            for k, total in cur.items():
                proc, sni = k
                dst = None
                for key, s in self.mon.stats.items():
                    if s.sni == sni:
                        dst = s.dst
                        break
                is_agent = rules.is_known_agent_domain(sni)
                alert = ""
                if total > cfg.size_threshold:
                    alert = "warn"
                if k not in reported:
                    reported.add(k)
                    totals[k] = total
                    self.state.add_event(proc, sni, dst or "?", total, is_agent, alert)
                    if self.logger:
                        self.logger.log(
                            time.strftime("%H:%M:%S"), time.time(), proc, sni,
                            dst or "?", total, is_agent, alert,
                        )
                elif total > totals[k]:
                    delta = total - totals[k]
                    totals[k] = total
                    self.state.add_event(proc, sni, dst or "?", delta, is_agent, alert)
                    if self.logger:
                        self.logger.log(
                            time.strftime("%H:%M:%S"), time.time(), proc, sni,
                            dst or "?", delta, is_agent, alert,
                        )

    def start_mitm(self) -> dict:
        """启动 MITM 代理，返回状态。"""
        if self._mitm_running:
            return {"ok": False, "error": "MITM 代理已在运行"}
        from core import mitm, canary
        # 加载蜜罐和指纹
        tokens = []
        fingerprints = []
        cdata = canary.load_canary(".")
        if cdata:
            tokens.append(cdata["token"])
        fp_data = canary.load_fingerprints(".")
        if fp_data:
            fingerprints = fp_data.get("hashes", [])
        def on_alert(level, msg):
            if level == "critical":
                self.state.add_event("MITM", "蜜罐/指纹命中", msg, 0, True, "critical")
        try:
            self._mitm_proxy = mitm.MitmProxy(
                port=self._mitm_port,
                canary_tokens=tokens,
                fingerprints=fingerprints,
                on_alert=on_alert,
                state=self.state,
            )
            self._mitm_proxy.start()
            self._mitm_running = True
            ca_path, _ = mitm.ensure_ca()
            return {"ok": True, "port": self._mitm_port, "ca_path": ca_path,
                    "canary_count": len(tokens), "fp_count": len(fingerprints)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def stop_mitm(self) -> dict:
        """停止 MITM 代理。"""
        if not self._mitm_running:
            return {"ok": False, "error": "MITM 代理未运行"}
        try:
            self._mitm_proxy.stop()
            self._mitm_running = False
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def mitm_status(self) -> dict:
        from core import mitm
        ca_path, _ = mitm.ensure_ca()
        return {"running": self._mitm_running, "port": self._mitm_port, "ca_path": ca_path}

    def launch_agent(self, cmd: str) -> dict:
        """启动被监控 Agent，自动注入代理环境变量。
        支持简写名称（trae/qoder/cursor...），自动探测安装路径。"""
        import subprocess, shlex
        if self._agent_process and self._agent_process.poll() is None:
            return {"ok": False, "error": "已有 Agent 在运行，请先终止"}
        if not self._mitm_running:
            return {"ok": False, "error": "请先启动 MITM 代理"}

        # 将简写名称解析为实际路径
        resolved = _resolve_agent_cmd(cmd)
        if not resolved:
            return {"ok": False, "error": f"找不到程序: {cmd}"}

        from core import mitm, keylog
        ca_path, _ = mitm.ensure_ca()

        # Electron 应用需要 --proxy-server 参数才能走代理
        is_electron = any(x in resolved.lower() for x in
                          ["trae", "qoder", "cursor", "codebuddy", "windsurf"])
        if is_electron:
            resolved = f'"{resolved}" --proxy-server=http://127.0.0.1:{self._mitm_port}'

        args = ["cmd", "/c", resolved] if (" " in resolved and resolved[0] != '"') else shlex.split(resolved)

        env = os.environ.copy()
        env["HTTPS_PROXY"] = f"http://127.0.0.1:{self._mitm_port}"
        env["NODE_EXTRA_CA_CERTS"] = ca_path
        env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"

        try:
            p = subprocess.Popen(
                args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=None,
            )
        except FileNotFoundError:
            return {"ok": False, "error": f"找不到命令: {cmd}"}

        self._agent_process = p
        with self._agent_lock:
            self._agent_output.append(f"[启动] {cmd}")
        def _reader():
            for line in p.stdout:
                with self._agent_lock:
                    self._agent_output.append(line.rstrip()[:200])
                if len(self._agent_output) > 200:
                    with self._agent_lock:
                        self._agent_output[:] = self._agent_output[-100:]
        threading.Thread(target=_reader, daemon=True).start()
        return {"ok": True, "pid": p.pid, "cmd": cmd}

    def kill_agent(self) -> dict:
        if not self._agent_process or self._agent_process.poll() is not None:
            return {"ok": False, "error": "无运行中的 Agent"}
        self._agent_process.terminate()
        return {"ok": True}

    def agent_output(self) -> list[str]:
        with self._agent_lock:
            out = list(self._agent_output)
            self._agent_output.clear()
        return out

    def serve(self) -> None:
        state = self.state
        mon = self.mon
        srv_self = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass  # 静默 HTTP 日志

            def do_GET(self):
                if self.path == "/" or self.path.startswith("/?"):
                    self._serve_html()
                elif self.path.startswith("/api/events"):
                    since = 0
                    if "?" in self.path:
                        from urllib.parse import urlparse, parse_qs
                        q = parse_qs(urlparse(self.path).query)
                        since = float(q.get("since", ["0"])[0])
                    self._send_json(state.events_json(since))
                elif self.path == "/api/stats":
                    self._send_json(state.stats_json())
                elif self.path == "/api/bodies":
                    self._send_json(state.bodies_json())
                elif self.path == "/api/alerts":
                    self._send_json(state.alerts_json())
                elif self.path == "/api/mitm/status":
                    self._send_json(json.dumps(srv_self.mitm_status(), ensure_ascii=False))
                elif self.path == "/api/mitm/output":
                    self._send_json(json.dumps(srv_self.agent_output(), ensure_ascii=False))
                else:
                    self.send_error(404)

            def do_POST(self):
                if self.path == "/api/mitm/start":
                    result = srv_self.start_mitm()
                    self._send_json(json.dumps(result, ensure_ascii=False))
                elif self.path == "/api/mitm/stop":
                    result = srv_self.stop_mitm()
                    self._send_json(json.dumps(result, ensure_ascii=False))
                elif self.path == "/api/mitm/launch":
                    length = int(self.headers.get("Content-Length", 0))
                    body = self.rfile.read(length).decode("utf-8") if length else "{}"
                    try:
                        data = json.loads(body)
                        result = srv_self.launch_agent(data.get("cmd", ""))
                    except Exception:
                        result = {"ok": False, "error": "invalid JSON"}
                    self._send_json(json.dumps(result, ensure_ascii=False))
                elif self.path == "/api/mitm/kill":
                    result = srv_self.kill_agent()
                    self._send_json(json.dumps(result, ensure_ascii=False))
                else:
                    self.send_error(404)

            def _serve_html(self):
                html_path = os.path.join(_UI_DIR, "dashboard.html")
                if os.path.exists(html_path):
                    with open(html_path, "r", encoding="utf-8") as f:
                        html = f.read()
                else:
                    html = "<h1>dashboard.html not found</h1>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html.encode("utf-8"))

            def _send_json(self, data: str):
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(data.encode("utf-8"))

        server = HTTPServer(("127.0.0.1", self.port), Handler)
        server.allow_reuse_address = True
        url = f"http://127.0.0.1:{self.port}"
        print(f"面板已启动: {url}  (Ctrl-C 停止)")
        print(f"网卡: {mon.iface_used}  进程归因: {'可用' if self.pa.available else '不可用'}")
        if self.logger:
            print(f"日志落盘: {self.logger.csv_path or self.logger.json_path}")
        if self.auto_open:
            import webbrowser
            import threading as _thr
            def _open():
                time.sleep(0.5)
                webbrowser.open(url)
            _thr.Thread(target=_open, daemon=True).start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n停止...")
        finally:
            server.shutdown()
