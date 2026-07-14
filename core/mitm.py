"""MITM 深度检测模式：拦截 Node 代理 HTTPS，扫描请求体中的蜜罐令牌和仓库指纹。

架构：
  mitmproxy 作为本地代理（127.0.0.1:8080），MitmAddon 拦截每个请求/响应。
  对请求体做：(1) 蜜罐令牌匹配 (2) 仓库文件指纹匹配。
  命中时回调 on_alert(level, message)。

用法：
  proxy = MitmProxy(port=8080, canary_tokens=[...], fingerprints=[...], on_alert=...)
  proxy.start()
  # 启动 Node 代理时注入 HTTPS_PROXY=127.0.0.1:8080 + NODE_EXTRA_CA_CERTS=<ca_path>

CA 证书：
  首次运行时自动生成 self-signed CA，存储到 config/mitm_ca.pem。
  需手动安装为受信任的根证书颁发机构（Windows: certmgr.msc）。
"""
from __future__ import annotations

import os as _os
import threading
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_CA_DIR = _ROOT / "config"
_CA_PATH = _CA_DIR / "mitm_ca.pem"
_CA_KEY = _CA_DIR / "mitm_ca_key.pem"


def ensure_ca() -> tuple[str, str]:
    """确保存在自签 CA 证书。返回 (cert_path, key_path)。"""
    _CA_DIR.mkdir(parents=True, exist_ok=True)
    if _CA_PATH.exists() and _CA_KEY.exists():
        return str(_CA_PATH), str(_CA_KEY)

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AgentMon MITM CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AgentMon MITM CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    _CA_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _CA_KEY.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    return str(_CA_PATH), str(_CA_KEY)


class MitmAddon:
    def __init__(self, canary_tokens: list[str], fingerprints: list[str],
                 on_alert, state=None):
        self.canary = set(canary_tokens)
        self.fingerprints = set(fingerprints)
        self.on_alert = on_alert
        self.state = state  # DashboardState 引用

    def request(self, flow):
        host = flow.request.pretty_host
        url = flow.request.pretty_url[:120]
        method = flow.request.method
        try:
            body = flow.request.get_text()
        except Exception:
            body = ""
        # 推送到面板
        if self.state and body:
            ch = any(t in body for t in self.canary)
            fh = any(f in body for f in self.fingerprints)
            self.state.record_body(method, host, url, body, ch, fh)
        if not body:
            return
        for token in self.canary:
            if token in body:
                self.on_alert("critical", f"请求体含蜜罐令牌！{host} {url[:80]}")
                return
        for fp in self.fingerprints:
            if fp in body:
                self.on_alert("critical", f"请求体含仓库指纹！{host} {url[:80]}")
                return


class MitmProxy:
    def __init__(self, port: int = 8080, canary_tokens=None, fingerprints=None,
                 on_alert=None, state=None):
        self.port = port
        self.canary_tokens = canary_tokens or []
        self.fingerprints = fingerprints or []
        self.on_alert = on_alert or (lambda l, m: print(f"[{l.upper()}] {m}"))
        self.state = state
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self):
        ca_path, ca_key = ensure_ca()
        # mitmproxy 的 options 需要在主线程配置
        self._thread = threading.Thread(target=self._run, args=(ca_path, ca_key), daemon=True)
        self._thread.start()

    def _run(self, ca_path, ca_key):
        import asyncio
        from mitmproxy.options import Options as MOptions
        from mitmproxy.master import Master

        opts = MOptions(
            listen_host="127.0.0.1",
            listen_port=self.port,
            ssl_insecure=True,
        )
        # certs format in v11: [f"*={cert_path},{key_path}"]
        opts.update(certs=[f"*={ca_path},{ca_key}"])

        async def _main():
            master = Master(opts)
            master.addons.add(MitmAddon(
                self.canary_tokens, self.fingerprints,
                self.on_alert, self.state,
            ))
            # 后台 stop 监控
            async def _stop_watcher():
                while not self._stop.is_set():
                    await asyncio.sleep(0.5)
                master.shutdown()
            asyncio.ensure_future(_stop_watcher())
            await master.run()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_main())
        finally:
            loop.close()

    def stop(self):
        self._stop.set()
