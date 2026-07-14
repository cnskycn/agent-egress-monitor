"""SSLKEYLOGFILE 启动器。

以注入 SSLKEYLOGFILE 环境变量的方式启动 AI 编码代理，使其在建立
TLS 连接时把会话密钥写入指定文件，供后续 tshark 解密请求体。
适用于 Node 系代理（Claude/Grok/Codex/Cursor/Cline）。
"""
from __future__ import annotations

import os
import subprocess
import pathlib


def keylog_path_for(session_dir: str) -> str:
    p = pathlib.Path(session_dir)
    p.mkdir(parents=True, exist_ok=True)
    return str(p / "sslkeylog.txt")


def launch_with_keylog(command, keylog_path, cwd=None, env_extra=None):
    env = dict(os.environ)
    env["SSLKEYLOGFILE"] = str(keylog_path)
    if env_extra:
        env.update(env_extra)
    return subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
