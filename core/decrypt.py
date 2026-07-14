"""tshark 解密封装。

配合 SSLKEYLOGFILE 产出的密钥文件，调用 tshark 解密 pcap 中的
TLS 应用数据，提取 HTTP/2 请求的方法、Host、URI 与请求体。
需要系统安装 Wireshark（提供 tshark）。缺失时优雅报错。
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def decrypt_pcap(pcap_path, keylog_path, extra_display: str = "") -> list[dict]:
    if not tshark_available():
        raise RuntimeError(
            "未找到 tshark。请安装 Wireshark（勾选把 tshark 加入 PATH）以启用内容解密。"
        )
    disp = "http2 or http"
    if extra_display:
        disp = f"({disp}) and ({extra_display})"
    cmd = [
        "tshark", "-r", str(pcap_path),
        "-o", f"tls.keylog_file:{keylog_path}",
        "-Y", disp,
        "-T", "json",
        "-e", "http2.headers.method",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-e", "http.file_data",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError("tshark 执行失败: " + (res.stderr or "")[:500])
    try:
        rows = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    for row in rows:
        if "_source" not in row or "layers" not in row["_source"]:
            continue
        layers = row["_source"]["layers"]
        get = lambda k: (layers.get(k, [None])[0] if isinstance(layers.get(k), list) else layers.get(k))
        out.append({
            "method": get("http2.headers.method"),
            "host": get("http.host"),
            "uri": get("http.request.uri"),
            "body": get("http.file_data"),
        })
    return out
