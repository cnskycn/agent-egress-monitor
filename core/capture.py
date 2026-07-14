"""被动抓包（scapy + Npcap）。

在线解析出站 TLS 握手的 SNI，并统计本机发出的上行字节数。
纯被动、不影响被监控进程。
"""
from __future__ import annotations

import os as _os
import sys as _sys
import threading
from dataclasses import dataclass

# Windows Npcap 必须用原生 pcap API，否则 Wi-Fi 抓包会收到 Raw 而解析不了 IP 层。
if _os.name == "nt":
    try:
        from scapy.config import conf as _scapy_conf
        _scapy_conf.use_pcap = True
    except Exception:
        pass

from core import sni as sni_mod


def _is_admin() -> bool:
    """检测是否具有管理员/root 权限（抓包必需）。

    Windows 下 Npcap 在非管理员进程里调用 sniff 可能直接崩溃（C 层，
    Python try/except 捕获不到），因此必须在调用前主动判断并跳过。
    """
    if _os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    try:
        return _os.geteuid() == 0
    except Exception:
        return False


@dataclass
class ConnStat:
    sni: str | None = None
    uplink_bytes: int = 0
    dst: str | None = None
    sport: int | None = None
    tls_seen: bool = False


_PRIVATE_PREFIXES = (
    "10.", "192.168.", "127.", "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


def _is_private(ip: str) -> bool:
    return ip.startswith(_PRIVATE_PREFIXES)


def list_ifaces():
    """列出所有可用 Npcap 网卡名称及其 IPv4 地址。"""
    try:
        from scapy.arch.windows import get_windows_if_list
        from scapy.interfaces import IFACES
        IFACES.reload()  # 刷新接口缓存
        rows: list[dict] = []
        for info in get_windows_if_list():
            name = info.get("name") or info.get("friendly_name", "")
            desc = info.get("description", "")
            ips = info.get("ips", [])
            rows.append({
                "name": name,
                "desc": desc[:60],
                "ips": [ip for ip in ips if ip and ":" not in ip and ip != "0.0.0.0"],
            })
        return rows
    except Exception as e:
        print(f"[WARN] 无法列出网卡: {e}")
        return []


def _pick_best_iface():
    """自动选最可能的主网卡（优先 WLAN/Wi-Fi，其次有线，取第一个有非回环 IPv4 的）。"""
    try:
        from scapy.arch.windows import get_windows_if_list
        candidates = []
        for info in get_windows_if_list():
            ips = [ip for ip in info.get("ips", []) if ip and ":" not in ip and ip != "0.0.0.0"
                   and not ip.startswith("127.")]
            if not ips:
                continue
            name = info.get("name") or ""
            desc = (info.get("description") or "").lower()
            wlan_score = (
                0 if "wlan" in name.lower() or "wi-fi" in desc or "wireless" in desc else 1
            )
            candidates.append((wlan_score, name, ips))
        if candidates:
            candidates.sort(key=lambda x: (x[0], x[1]))
            return candidates[0][1]
    except Exception:
        pass
    return None


class CaptureMonitor:
    def __init__(self, iface=None, bpf: str = "tcp port 443 or tcp port 8443"):
        self.iface = iface
        self.bpf = bpf
        self.stats: dict[tuple, ConnStat] = {}
        self.error: str | None = None
        self._pkt_received: int = 0
        self._cnt_ip_tcp: int = 0
        self._cnt_raw: int = 0
        self._cnt_tls16: int = 0
        self._samples: list[str] = []  # 前 3 个包的简要描述
        self._iface_used: str | None = None
        self._stop = threading.Event()
        self._thread = None

    @property
    def pkt_received(self) -> int:
        return self._pkt_received

    @property
    def cnt_ip_tcp(self) -> int:
        return self._cnt_ip_tcp

    @property
    def cnt_raw(self) -> int:
        return self._cnt_raw

    @property
    def cnt_tls16(self) -> int:
        return self._cnt_tls16

    @property
    def samples(self) -> list[str]:
        return self._samples

    @property
    def iface_used(self) -> str | None:
        return self._iface_used

    def _handle(self, pkt) -> None:
        self._pkt_received += 1
        if len(self._samples) < 3:
            self._samples.append(str(pkt.summary())[:100])
        try:
            from scapy.layers.inet import IP, TCP
            from scapy.packet import Raw
            from scapy.layers.l2 import Ether

            # Windows Wi-Fi 上 scapy 可能无法自动解析链路层，
            # 收到的包全是 Raw。此时手动把原始字节当 Ethernet 帧重新解析。
            if not pkt.haslayer(IP):
                raw_data = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else bytes(pkt)
                if len(raw_data) < 14:
                    return
                eth_type = int.from_bytes(raw_data[12:14], "big")
                if eth_type != 0x0800:  # 非 IPv4
                    return
                pkt = Ether(raw_data)

            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                return
            self._cnt_ip_tcp += 1
            ip = pkt[IP]
            tcp = pkt[TCP]
            if not pkt.haslayer(Raw):
                return
            self._cnt_raw += 1
            payload = bytes(pkt[Raw].load)
            key = (ip.src, f"{ip.dst}:{tcp.dport}")
            st = self.stats.setdefault(key, ConnStat())
            st.dst = f"{ip.dst}:{tcp.dport}"
            st.sport = int(tcp.sport)
            if _is_private(ip.src):
                st.uplink_bytes += len(payload)
            if payload and payload[0] == 0x16:
                self._cnt_tls16 += 1
                try:
                    info = sni_mod.parse_client_hello(payload)
                    st.tls_seen = True
                    st.sni = info.sni
                    st.dst = f"{ip.dst}:{tcp.dport}"
                except Exception:
                    pass
        except Exception:
            pass

    def start(self, timeout: float | None = None) -> None:
        if not _is_admin():
            self.error = "需要管理员权限才能抓包（非管理员下 Npcap 可能使进程崩溃）"
            return
        if self.iface is None:
            self.iface = _pick_best_iface()
        self._iface_used = self.iface or "(auto)"
        self._thread = threading.Thread(target=self._run, args=(timeout,), daemon=True)
        self._thread.start()

    def _run(self, timeout) -> None:
        try:
            from scapy.sendrecv import sniff
            sniff(
                iface=self.iface,
                filter=self.bpf,
                prn=self._handle,
                stop_filter=lambda p: self._stop.is_set(),
                timeout=timeout,
                store=False,
            )
        except Exception as e:  # 多数情况是无管理员权限 / Npcap 不可用
            self.error = str(e)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
