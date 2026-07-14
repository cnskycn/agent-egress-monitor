"""TLS ClientHello 解析（纯 Python，无依赖）。

用于在不解密的情况下，从出站 TLS 握手中提取目标域名(SNI)、
ALPN 与 TLS 版本。是元数据级检测的核心。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class ClientHelloInfo:
    sni: str | None
    alpn: list[str]
    tls_version: str | None
    raw_version: int | None


def parse_client_hello(data: bytes) -> ClientHelloInfo:
    """解析 TLS ClientHello。

    `data` 可从 TLS 记录层(首字节 0x16)或握手层开始。
    返回 ClientHelloInfo；结构非法时抛 ValueError。
    """
    if not data:
        raise ValueError("empty")
    off = 0
    raw_version = None
    # TLS 记录层（可选）
    if data[0] == 0x16:
        if len(data) < 5:
            raise ValueError("tls record too short")
        raw_version = struct.unpack(">H", data[1:3])[0]
        off = 5
    # 握手层
    if off >= len(data) or data[off] != 0x01:
        raise ValueError("not client_hello (type=%s)" % (data[off] if off < len(data) else "eof"))
    off += 1
    if off + 3 > len(data):
        raise ValueError("no handshake length")
    off += 3  # 3 字节握手长度，这里只用 body 起点
    # ClientHello body
    if off + 2 > len(data):
        raise ValueError("no version")
    raw_version = struct.unpack(">H", data[off:off + 2])[0]
    off += 2
    off += 32  # random
    if off >= len(data):
        raise ValueError("no session_id len")
    off += 1 + data[off]  # session_id
    if off + 2 > len(data):
        raise ValueError("no cipher len")
    cs_len = struct.unpack(">H", data[off:off + 2])[0]
    off += 2 + cs_len
    if off >= len(data):
        raise ValueError("no compression len")
    off += 1 + data[off]  # compression methods
    if off + 2 > len(data):
        return ClientHelloInfo(None, [], _ver(raw_version), raw_version)
    ext_total = struct.unpack(">H", data[off:off + 2])[0]
    off += 2
    ext_end = min(off + ext_total, len(data))
    sni = None
    alpn: list[str] = []
    while off + 4 <= ext_end:
        ext_type = struct.unpack(">H", data[off:off + 2])[0]
        ext_len = struct.unpack(">H", data[off + 2:off + 4])[0]
        off += 4
        if off + ext_len > ext_end:
            break
        ext_data = data[off:off + ext_len]
        if ext_type == 0x0000:
            sni = _parse_sni(ext_data)
        elif ext_type == 0x0010:
            alpn = _parse_alpn(ext_data)
        off += ext_len
    return ClientHelloInfo(sni, alpn, _ver(raw_version), raw_version)


def _parse_sni(ext: bytes) -> str | None:
    if len(ext) < 2:
        return None
    off = 2  # 跳过 server_name_list 长度
    if off + 3 > len(ext):
        return None
    name_type = ext[off]
    off += 1
    name_len = struct.unpack(">H", ext[off:off + 2])[0]
    off += 2
    if name_type != 0 or off + name_len > len(ext):
        return None
    return ext[off:off + name_len].decode("utf-8", "replace")


def _parse_alpn(ext: bytes) -> list[str]:
    out: list[str] = []
    if len(ext) < 2:
        return out
    off = 2
    while off + 1 <= len(ext):
        l = ext[off]
        off += 1
        if off + l > len(ext):
            break
        out.append(ext[off:off + l].decode("utf-8", "replace"))
        off += l
    return out


def _ver(raw: int) -> str | None:
    if raw is None:
        return None
    return {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }.get(raw, "0x%04x" % raw)
