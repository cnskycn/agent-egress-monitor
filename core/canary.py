"""蜜罐令牌（canary）。

在仓库内植入带唯一高熵签名的诱饵文件。若其原文出现在任何出站
请求体中，即 100% 确认代码外泄。
"""
from __future__ import annotations

import secrets
import hashlib
import json
import pathlib


CANARY_DIR = ".agentmon"
CANARY_PREFIX = "canary-"
FINGERPRINT_FILE = "fingerprints.json"


def _scan_repo(repo_root, max_files: int = 200) -> list[str]:
    """扫描仓库源文件，返回 SHA256 哈希列表（跳过 .git / node_modules 等）。"""
    import os
    repo = pathlib.Path(repo_root)
    hashes = []
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv",
                 "dist", "build", ".next", ".agentmon"}
    skip_ext = {".pyc", ".pyo", ".exe", ".dll", ".so", ".dylib", ".class",
                ".jar", ".war", ".png", ".jpg", ".jpeg", ".gif", ".ico",
                ".mp3", ".mp4", ".wav", ".zip", ".tar", ".gz", ".7z"}
    for root, dirs, files in os.walk(str(repo)):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        for f in files:
            if len(hashes) >= max_files:
                break
            ext = os.path.splitext(f)[1].lower()
            if ext in skip_ext:
                continue
            try:
                data = pathlib.Path(root, f).read_bytes()
                if len(data) > 1024 * 1024:  # 跳过 >1MB 文件
                    continue
                h = hashlib.sha256(data).hexdigest()
                hashes.append(h[:16])  # 取前 16 字符节省空间
            except Exception:
                continue
    return hashes


def generate_fingerprints(repo_root) -> dict:
    repo = pathlib.Path(repo_root)
    d = repo / CANARY_DIR
    d.mkdir(exist_ok=True)
    hashes = _scan_repo(repo_root)
    data = {"hashes": hashes, "count": len(hashes)}
    (d / FINGERPRINT_FILE).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return {"path": str(d / FINGERPRINT_FILE), **data}


def load_fingerprints(repo_root) -> dict | None:
    path = pathlib.Path(repo_root) / CANARY_DIR / FINGERPRINT_FILE
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def generate_canary(repo_root, token_len: int = 32) -> dict:
    repo = pathlib.Path(repo_root)
    d = repo / CANARY_DIR
    d.mkdir(exist_ok=True)
    token = secrets.token_hex(token_len)
    fname = f"{CANARY_PREFIX}{secrets.token_hex(4)}.json"
    content = json.dumps(
        {
            "_agentmon_canary": True,
            "token": token,
            "hint": "decoy file; do NOT commit. detects repo exfiltration.",
        },
        indent=2,
    )
    (d / fname).write_text(content, encoding="utf-8")
    fp = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return {"path": str(d / fname), "token": token, "fingerprint": fp, "content": content}


def load_canary(repo_root) -> dict | None:
    d = pathlib.Path(repo_root) / CANARY_DIR
    if not d.exists():
        return None
    for f in d.glob(f"{CANARY_PREFIX}*.json"):
        try:
            content = f.read_text(encoding="utf-8")
            obj = json.loads(content)
            if obj.get("_agentmon_canary"):
                return {
                    "path": str(f),
                    "token": obj.get("token"),
                    "fingerprint": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    "content": content,
                }
        except Exception:
            continue
    return None
