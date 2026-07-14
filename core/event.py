"""出站流量事件模型。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class EgressEvent:
    timestamp: float
    src: Optional[str] = None
    dst: Optional[str] = None
    sni: Optional[str] = None
    uplink_bytes: int = 0
    tls_version: Optional[str] = None
    body_contains_canary: bool = False
    body_contains_fingerprint: bool = False
