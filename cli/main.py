"""agent-egress-monitor CLI。

子命令：
  selftest   运行 Phase 0 自测（SNI 解析 / SSLKEYLOGFILE / 实时抓包）
  monitor    实时抓包并输出告警事件（需管理员）
  launch     以注入 SSLKEYLOGFILE 的方式启动某个 AI 编码代理
  canary     在仓库内生成蜜罐诱饵文件
"""
from __future__ import annotations

import sys
import os
import argparse
import pathlib
import time
import json
import tempfile
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import sni, keylog, canary, capture, decrypt, rules, event as event_mod, procattr, dashboard as dash_mod, logger as logger_mod, tray as tray_mod, mitm as mitm_mod

NODE = os.environ.get("NODE_BIN", "node")


def build_client_hello(sni_host: str) -> bytes:
    """独立的 ClientHello 构造器，仅用于自测（与解析器代码路径不同）。"""
    import struct

    def ext_sni(s):
        name = s.encode()
        entry = b"\x00" + struct.pack(">H", len(name)) + name
        lst = struct.pack(">H", len(entry))
        return b"\x00\x00" + struct.pack(">H", len(lst + entry)) + lst + entry

    def ext_alpn(items):
        data = b"".join(bytes([len(p.encode())]) + p.encode() for p in items)
        body = struct.pack(">H", len(data)) + data
        return b"\x00\x10" + struct.pack(">H", len(body)) + body

    version = struct.pack(">H", 0x0303)
    random = b"\x00" * 32
    sid = b""
    cs = struct.pack(">H", 0x1301)
    csb = struct.pack(">H", len(cs)) + cs
    comp = b"\x00"
    compb = bytes([len(comp)]) + comp
    exts = ext_sni(sni_host) + ext_alpn(["h2", "http/1.1"])
    extb = struct.pack(">H", len(exts)) + exts
    body = version + random + bytes([len(sid)]) + sid + csb + compb + extb
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    rec = b"\x16" + struct.pack(">H", 0x0301) + struct.pack(">H", len(hs)) + hs
    return rec


def cmd_selftest(args) -> int:
    print("=== Phase 0 self-test ===")
    ok = True

    # 1) SNI 解析器
    try:
        ch = build_client_hello("api.anthropic.com")
        info = sni.parse_client_hello(ch)
        assert info.sni == "api.anthropic.com", info.sni
        assert "h2" in info.alpn
        print(f"[PASS] SNI 解析器: sni={info.sni} alpn={info.alpn} ver={info.tls_version}")
    except Exception as e:
        ok = False
        print(f"[FAIL] SNI 解析器: {e}")

    # 2) Node 是否尊重 SSLKEYLOGFILE（内容解密路径可行性）—— 本地 TLS 服务器，不依赖外网
    try:
        import ssl as _ssl
        import socket as _socket
        import threading as _threading
        import datetime as _dt
        from cryptography import x509 as _x509
        from cryptography.x509.oid import NameOID as _NameOID
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives import serialization as _ser
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

        _key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _cert = (
            _x509.CertificateBuilder()
            .subject_name(_x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(_x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, "localhost")]))
            .public_key(_key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=1))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
            .add_extension(_x509.SubjectAlternativeName([_x509.DNSName("localhost")]), critical=False)
            .sign(_key, _hashes.SHA256())
        )
        _cert_pem = _cert.public_bytes(_ser.Encoding.PEM)
        _key_pem = _key.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption())

        with tempfile.TemporaryDirectory() as td:
            _cert_path = os.path.join(td, "cert.pem")
            _key_path = os.path.join(td, "key.pem")
            with open(_cert_path, "wb") as f:
                f.write(_cert_pem)
            with open(_key_path, "wb") as f:
                f.write(_key_pem)
            kp = keylog.keylog_path_for(td)

            _ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            _ctx.load_cert_chain(_cert_path, _key_path)

            def _serve():
                _srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                _srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
                _srv.bind(("127.0.0.1", 8443))
                _srv.listen(1)
                try:
                    _conn, _ = _srv.accept()
                    with _ctx.wrap_socket(_conn, server_side=True) as _tls:
                        _tls.recv(4096)
                        _tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                except Exception:
                    pass
                finally:
                    _srv.close()

            _t = _threading.Thread(target=_serve, daemon=True)
            _t.start()

            _script = (
                "fetch('https://127.0.0.1:8443',{rejectUnauthorized:false})"
                ".then(r=>r.status)"
                ".catch(e=>{console.error('ERR',e.message);process.exit(2)})"
            )
            p = keylog.launch_with_keylog(
                [NODE, "-e", _script], kp,
                env_extra={"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
            )
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()
            _t.join(timeout=2)
            size = os.path.getsize(kp) if os.path.exists(kp) else 0
            if size > 0:
                print(f"[PASS] Node 写入 SSLKEYLOGFILE ({size} bytes) -> 内容解密路径可行")
            else:
                print("[INFO] Node 默认不自动写 SSLKEYLOGFILE（空文件）。内容解密需 MITM 代理或代理自身支持；元数据检测不受影响。")
    except FileNotFoundError:
        print("[SKIP] 未找到 node，跳过 SSLKEYLOGFILE 测试")
    except Exception as e:
        print(f"[SKIP] SSLKEYLOGFILE 测试异常: {e}")

    # 3) 实时抓包（需管理员 + Npcap）
    try:
        mon = capture.CaptureMonitor()
        mon.start(timeout=8)
        print("[INFO] 尝试实时抓包 8s（需要管理员权限）...")
        time.sleep(9)
        mon.stop()
        if mon.error:
            print(f"[SKIP] 实时抓包需要管理员权限: {mon.error}")
        else:
            found = [s for s in mon.stats.values() if s.tls_seen]
            if found:
                for s in found[:5]:
                    print(f"   SNI={s.sni} uplink={s.uplink_bytes}")
                print(f"[PASS] 实时抓包成功，捕获 {len(found)} 个 TLS 握手")
            else:
                print("[SKIP] 实时抓包未捕获（可能当前无 TLS 流量）")
    except Exception as e:
        print(f"[SKIP] 实时抓包异常: {e}")

    print("=== self-test done ===")
    return 0 if ok else 1


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f}KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.2f}MB"
    return f"{n / (1024 * 1024 * 1024):.2f}GB"


def _emit_line(now: str, proc: str, sni: str, dst: str | None,
                total: int, delta: int, is_new: bool, cfg) -> None:
    known = rules.is_known_agent_domain(sni)
    tag = " [AGENT]" if known else ""
    if is_new:
        print(f"[{now}] NEW  {proc} -> {sni}{tag} uplink={_fmt_bytes(total)} dst={dst or '?'}")
    else:
        print(f"[{now}]      {proc} -> {sni}{tag} +{_fmt_bytes(delta)} (total {_fmt_bytes(total)})")
    if total > cfg.size_threshold:
        print(f"        [WARN] 单连接上行超阈值 {_fmt_bytes(total)} -> 注意是否有整仓上传")


def _run_monitor_loop(mon, pa, args) -> None:
    cfg = rules.Config(size_threshold=args.size_threshold)
    reported: set = set()
    totals: dict = {}
    start_ts = time.time()
    diag_printed = False
    flog = None
    if getattr(args, "to_file", None):
        flog = logger_mod.EgressLogger(
            csv_path=args.to_file + ".csv", json_path=args.to_file + ".jsonl"
        )
        print(f"日志落盘: {args.to_file}.csv / .jsonl")
    try:
        while True:
            time.sleep(args.interval)
            now = time.strftime("%H:%M:%S")
            cur: dict = {}
            for key, s in list(mon.stats.items()):
                if not s.tls_seen or not s.sni:
                    continue
                proc = pa.lookup(s.sport) if s.sport else None
                proc = proc or "(unknown)"
                k = (proc, s.sni)
                cur[k] = cur.get(k, 0) + s.uplink_bytes
            for k in list(cur.keys()):
                proc, sni = k
                if args.only_proc and args.only_proc.lower() not in proc.lower():
                    del cur[k]
                    continue
                if args.known_only and not rules.is_known_agent_domain(sni):
                    del cur[k]
                    continue
            for k, total in cur.items():
                proc, sni = k
                dst = None
                for key, s in mon.stats.items():
                    if s.sni == sni:
                        dst = s.dst
                        break
                if k not in reported:
                    reported.add(k)
                    totals[k] = total
                    _emit_line(now, proc, sni, dst, total, 0, True, cfg)
                    if flog:
                        flog.log(now, time.time(), proc, sni, dst or "?", total,
                                 rules.is_known_agent_domain(sni), "")
                elif total > totals[k]:
                    delta = total - totals[k]
                    totals[k] = total
                    _emit_line(now, proc, sni, dst, total, delta, False, cfg)
                    if flog:
                        flog.log(now, time.time(), proc, sni, dst or "?", delta,
                                 rules.is_known_agent_domain(sni),
                                 "warn" if total > cfg.size_threshold else "")

            # 心跳诊断：运行超过 10s 仍无 TLS 流量时提示
            if not diag_printed and time.time() - start_ts > 10 and len(mon.stats) == 0:
                diag_printed = True
                pkts = mon.pkt_received
                iptcp = mon.cnt_ip_tcp
                raw = mon.cnt_raw
                tls16 = mon.cnt_tls16
                iface = mon.iface_used
                print(f"[{now}] 运行 10s，收包 {pkts} 个，其中 IP+TCP={iptcp}  Raw={raw}  TLS_0x16={tls16}")
                if mon.samples:
                    print(f"[{now}] 前 3 个包的摘要:")
                    for s in mon.samples:
                        print(f"[{now}]   {s}")
                if pkts > 0 and iptcp == 0:
                    print(f"[{now}] 有包但没有 IP+TCP 层 → scapy 可能解析链路层失败")
                    print(f"[{now}] 请 Ctrl-C 停止，换网卡试试。已知可用的有 IP 的网卡:")
                    rows = capture.list_ifaces()
                    for r in rows:
                        if r["ips"]:
                            print(f"    {r['name']} ({', '.join(r['ips'])})")
                elif iptcp > 0 and raw == 0:
                    print(f"[{now}] IP+TCP 有 {iptcp} 个但全部无应用层 Raw 数据(纯 TCP 控制包)")
                    print(f"[{now}] 持续监控即可——等新的 TLS 连接建立就会看到数据")
                else:
                    print(f"[{now}] 如果一直无 TLS 流量，请 Ctrl-C 停止后换网卡再试")
    except KeyboardInterrupt:
        print("\n停止监控")
    finally:
        if flog:
            flog.close()
            print(f"日志已保存: {args.to_file}.csv / {args.to_file}.jsonl")


def cmd_monitor(args) -> int:
    # --list-ifaces：列出网卡后退出
    if getattr(args, "list_ifaces", False):
        print("=== 可用 Npcap 网卡 ===")
        rows = capture.list_ifaces()
        if not rows:
            print("无法获取网卡列表（Npcap 是否已安装？）")
            return 1
        for r in rows:
            ips = ", ".join(r["ips"]) if r["ips"] else "(无 IP)"
            print(f"  {r['name']}")
            print(f"    IP: {ips}  |  {r['desc']}")
        return 0

    pa = procattr.ProcAttr(refresh=args.proc_refresh)
    pa.start()

    if getattr(args, "demo", False):
        print("=== DEMO 输出预览（无需管理员，仅展示格式）===")
        now = time.strftime("%H:%M:%S")
        cfg = rules.Config(size_threshold=args.size_threshold)
        samples = [
            ("claude.exe", "api.anthropic.com", "203.0.113.5:443", 4_200, 4_200, True),
            ("cursor.exe", "api2.cursor.com", "203.0.113.5:443", 980_000, 975_800, False),
            ("chrome.exe", "api.anthropic.com", "198.51.100.7:443", 130_000, 130_000, True),
            ("node.exe", "api.x.ai", "192.0.2.9:443", 2_400_000, 2_400_000, True),
            ("Code.exe", "github.com", "140.82.121.4:443", 8_800, 8_800, True),
        ]
        for proc, sni, dst, total, delta, is_new in samples:
            _emit_line(now, proc, sni, dst, total, delta, is_new, cfg)
        print("=== 预览结束（真实运行请用管理员身份执行 monitor）===")
        return 0

    mon = capture.CaptureMonitor(iface=args.iface if hasattr(args, "iface") else None)
    try:
        mon.start()
    except Exception as e:
        print(f"抓包启动失败（需管理员 + Npcap）: {e}")
        return 1
    if not capture._is_admin():
        print("[WARN] 当前不是管理员，抓包可能崩溃或被跳过。请右键以管理员身份运行。")
    print(f"开始监控（Ctrl-C 停止）... 进程归因: {'可用' if pa.available else '不可用'}  网卡: {mon.iface_used}")
    print("提示：先用无过滤模式看清目标代理的进程名与域名，再用 --only-proc 过滤")
    _run_monitor_loop(mon, pa, args)
    mon.stop()
    return 0


def cmd_launch(args) -> int:
    import shlex
    cmd = shlex.split(args.cmd)
    kp = keylog.keylog_path_for(args.session_dir)
    print(f"以 SSLKEYLOGFILE={kp} 启动: {' '.join(cmd)}")
    p = keylog.launch_with_keylog(cmd, kp, cwd=args.cwd)
    try:
        for line in p.stdout:
            print(line, end="")
    except KeyboardInterrupt:
        p.terminate()
    return 0


def cmd_dashboard(args) -> int:
    if not capture._is_admin():
        print("[WARN] 当前不是管理员，抓包可能无法工作。请右键以管理员身份运行。")
    csv_path = args.to_file + ".csv" if args.to_file else None
    json_path = args.to_file + ".jsonl" if args.to_file else None
    srv = dash_mod.DashboardServer(
        port=args.port, iface=args.iface,
        csv_path=csv_path, json_path=json_path,
        auto_open=not getattr(args, "no_browser", False),
    )
    srv.start()
    if srv.mon.error:
        print(f"抓包启动失败: {srv.mon.error}")
        return 1
    srv.serve()
    srv.stop()
    return 0


def cmd_tray(args) -> int:
    if not capture._is_admin():
        print("[WARN] 当前不是管理员，抓包可能无法工作。请右键以管理员身份运行。")
    csv_path = args.to_file + ".csv" if args.to_file else None
    json_path = args.to_file + ".jsonl" if args.to_file else None
    app = tray_mod.TrayApp(
        iface=args.iface, port=args.port,
        csv_path=csv_path, json_path=json_path,
    )
    app.run()
    return 0


def cmd_mitm(args) -> int:
    import shlex
    # 生成/加载 CA 证书
    ca_path, ca_key = mitm_mod.ensure_ca()
    print(f"CA 证书: {ca_path}")
    print(f"请先安装 CA 为受信任根证书：certmgr.msc → 受信任的根证书颁发机构 → 导入 {ca_path}")
    print()

    # 加载蜜罐和指纹
    repo = args.repo or "."
    tokens = []
    fingerprints = []
    cdata = canary.load_canary(repo)
    if cdata:
        tokens.append(cdata["token"])
        print(f"蜜罐令牌: {cdata['path']}")
    fp_data = canary.load_fingerprints(repo)
    if fp_data:
        fingerprints.extend(fp_data.get("hashes", []))
        print(f"仓库指纹: {len(fingerprints)} 个文件哈希")

    # 启动 MITM 代理
    alerts = []
    def on_alert(level, msg):
        alerts.append((level, msg))
        print(f"\n[MITM {level.upper()}] {msg}")

    proxy = mitm_mod.MitmProxy(
        port=args.mitm_port, canary_tokens=tokens,
        fingerprints=fingerprints, on_alert=on_alert,
    )
    proxy.start()
    print(f"MITM 代理已启动: 127.0.0.1:{args.mitm_port}")

    # 启动目标代理
    import shlex as _shlx
    cmd = _shlx.split(args.cmd)
    kp = keylog.keylog_path_for(args.session_dir)
    print(f"以代理模式启动: {' '.join(cmd)}")
    p = keylog.launch_with_keylog(
        cmd, kp, cwd=args.cwd,
        env_extra={
            "HTTPS_PROXY": f"http://127.0.0.1:{args.mitm_port}",
            "NODE_EXTRA_CA_CERTS": ca_path,
            "NODE_TLS_REJECT_UNAUTHORIZED": "0",
        },
    )
    try:
        for line in p.stdout:
            print(line, end="")
    except KeyboardInterrupt:
        p.terminate()
    proxy.stop()
    print("\nMITM 模式结束")
    return 0


def cmd_canary(args) -> int:
    if args.action == "gen":
        res = canary.generate_canary(args.repo)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        print(f"\n已将蜜罐写入 {res['path']}（请勿提交到版本库）")
    else:
        res = canary.load_canary(args.repo)
        print(json.dumps(res, indent=2, ensure_ascii=False) if res else "未找到蜜罐")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="agentmon", description="AI 编码代理数据外泄监控（Phase 0 PoC）")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("selftest", help="运行 Phase 0 自测")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("monitor", help="实时抓包监控（可按进程/已知域名过滤）")
    p.add_argument("--size-threshold", type=int, default=1_000_000,
                   help="单连接上行超此字节数即告警（默认 1MB）")
    p.add_argument("--only-proc", default=None,
                   help="仅显示进程名含该子串的流量（如 claude / cursor）")
    p.add_argument("--known-only", action="store_true",
                   help="仅显示已知 AI/云/代理域名")
    p.add_argument("--proc-refresh", type=float, default=2.0,
                   help="进程映射刷新间隔（秒）")
    p.add_argument("--interval", type=float, default=2.0,
                   help="输出轮询间隔（秒）")
    p.add_argument("--demo", action="store_true",
                   help="仅预览输出格式（无需管理员）")
    p.add_argument("--iface", default=None,
                   help="指定 Npcap 网卡名称（如 \\Device\\NPF_{...}）；不指定则自动选")
    p.add_argument("--list-ifaces", action="store_true",
                   help="列出可用 Npcap 网卡及其 IP，然后退出")
    p.add_argument("--to-file", default=None,
                   help="落盘日志前缀（自动追加 .csv 和 .jsonl）")
    p.set_defaults(func=cmd_monitor)

    p = sub.add_parser("dashboard", help="启动本地 Web 面板（浏览器实时查看）")
    p.add_argument("--port", type=int, default=9876, help="HTTP 端口（默认 9876）")
    p.add_argument("--iface", default=None, help="指定 Npcap 网卡名称")
    p.add_argument("--to-file", default=None, help="落盘日志前缀")
    p.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    p.set_defaults(func=cmd_dashboard)

    p = sub.add_parser("tray", help="系统托盘常驻（任务栏图标，右键菜单）")
    p.add_argument("--port", type=int, default=9876, help="HTTP 端口（默认 9876）")
    p.add_argument("--iface", default=None, help="指定 Npcap 网卡名称")
    p.add_argument("--to-file", default=None, help="落盘日志前缀")
    p.set_defaults(func=cmd_tray)

    p = sub.add_parser("mitm", help="MITM 深度模式（蜜罐+指纹内容级检测）")
    p.add_argument("--cmd", required=True, help='代理启动命令')
    p.add_argument("--repo", default=".", help="仓库目录（读取蜜罐和指纹）")
    p.add_argument("--mitm-port", type=int, default=8080, help="MITM 代理端口")
    p.add_argument("--session-dir", default="./.agentmon_session")
    p.add_argument("--cwd", default=None)
    p.set_defaults(func=cmd_mitm)

    p = sub.add_parser("launch", help="以密钥日志启动代理")
    p.add_argument("--cmd", required=True, help='代理启动命令，如 "claude"')
    p.add_argument("--session-dir", default="./.agentmon_session")
    p.add_argument("--cwd", default=None)
    p.set_defaults(func=cmd_launch)

    p = sub.add_parser("canary", help="蜜罐令牌管理")
    p.add_argument("action", choices=["gen", "show"])
    p.add_argument("--repo", default=".")
    p.set_defaults(func=cmd_canary)

    args = ap.parse_args()
    if not getattr(args, "cmd", None):
        # 无参数双击 = 默认进入系统托盘模式，自动检测网卡
        print("Agent Egress Monitor — 双击启动，托盘模式")
        import argparse as _ap
        tray_args = _ap.Namespace(
            cmd="tray", port=9876, iface=None, to_file=None,
        )
        return cmd_tray(tray_args)
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception:
        import traceback as _tb
        _tb.print_exc()
        raise SystemExit(1)
