"""自动配置向导——让工具开箱即用。

首次运行自动完成：
  1. 检测最佳抓包网卡（Wi-Fi 优先）
  2. 生成 MITM CA 证书
  3. certutil 自动安装 CA 到受信任根证书（需管理员）
  4. 生成蜜罐令牌
  5. 扫描仓库指纹
  6. 保存到 config/agentmon.json

之后其他命令直接读取配置，零手动操作。
"""
from __future__ import annotations

import json
import os as _os
import pathlib
import subprocess

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_CONFIG_PATH = _ROOT / "config" / "agentmon.json"


def detect_iface() -> str | None:
    """自动检测最佳抓包网卡。返回名称如 'WLAN'，失败返回 None。"""
    from core.capture import _pick_best_iface, list_ifaces
    best = _pick_best_iface()
    if best:
        return best
    # fallback: 列出所有接口，返回第一个有 IP 的
    rows = list_ifaces()
    for r in rows:
        if r.get("ips"):
            return r["name"]
    return None


def install_ca_cert(cert_path: str) -> bool:
    """用 certutil 将 CA 证书安装到 Windows 受信任根证书颁发机构。需管理员。"""
    if _os.name != "nt":
        return False
    try:
        result = subprocess.run(
            ["certutil", "-addstore", "-f", "Root", cert_path],
            capture_output=True, timeout=30,
            encoding="gbk", errors="replace",
        )
        return result.returncode == 0
    except Exception:
        return False


def run(repo_root: str | None = None,
        iface: str | None = None) -> dict:
    """执行完整自动配置。返回配置字典。"""
    import time

    config: dict = {}
    repo = pathlib.Path(repo_root) if repo_root else _ROOT.parent
    print("=== AgentMon 自动配置 ===")

    # 1. 网卡
    iface_name = iface or detect_iface()
    config["iface"] = iface_name
    print(f"[1/5] 抓包网卡: {iface_name or '(未检测到，请手动指定 --iface)'}")

    # 2. CA 证书
    from core import mitm
    ca_path, ca_key = mitm.ensure_ca()
    config["ca_cert"] = str(ca_path)
    config["ca_key"] = str(ca_key)
    print(f"[2/5] MITM CA 证书: {ca_path}")

    # 3. 安装 CA（需管理员）
    installed = install_ca_cert(ca_path)
    config["ca_installed"] = installed
    if installed:
        print("[3/5] CA 证书已安装到受信任根证书")
    else:
        print("[3/5] CA 证书安装失败（可能缺管理员权限），MITM 模式需手动安装")

    # 4. 蜜罐令牌
    from core import canary
    canary_data = canary.load_canary(str(repo)) or canary.generate_canary(str(repo))
    config["canary_token"] = canary_data["token"]
    config["canary_path"] = canary_data["path"]
    print(f"[4/5] 蜜罐令牌: {canary_data['path']}")

    # 5. 仓库指纹
    fp_data = canary.load_fingerprints(str(repo)) or canary.generate_fingerprints(str(repo))
    config["fingerprints"] = fp_data.get("hashes", [])
    config["fingerprint_count"] = fp_data.get("count", 0)
    print(f"[5/5] 仓库指纹: {fp_data['count']} 个文件哈希")

    # 保存
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n配置已保存: {_CONFIG_PATH}")
    print("开箱即用！运行 agentmon start 即可开始监控。")
    return config


def load_config() -> dict | None:
    """读取已保存的配置。"""
    if not _CONFIG_PATH.exists():
        return None
    try:
        return json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None
