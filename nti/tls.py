"""Lightweight TLS parsing: record detection, ClientHello -> SNI / JA3."""

from __future__ import annotations

import hashlib

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

CT_HANDSHAKE = 22
CT_APPDATA = 23


def is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def tls_record_info(data: bytes):
    """Return (content_type, version, length) if data looks like a TLS record."""
    if len(data) < 5:
        return None
    ctype, major, minor = data[0], data[1], data[2]
    if ctype not in (20, 21, 22, 23) or major != 3 or minor > 4:
        return None
    return ctype, (major << 8) | minor, int.from_bytes(data[3:5], "big")


def _u16(buf: bytes, i: int) -> int:
    if i + 2 > len(buf):
        raise IndexError
    return int.from_bytes(buf[i:i + 2], "big")


def parse_client_hello(data: bytes):
    """Parse a TLS ClientHello.

    Returns:
        None                      -> not a ClientHello
        {"incomplete": True}      -> looks like one but more bytes are needed
        dict with sni/ja3/...     -> parsed successfully
    """
    info = tls_record_info(data)
    if not info or info[0] != CT_HANDSHAKE:
        return None
    rec_len = info[2]
    if len(data) < 5 + rec_len:
        if len(data) >= 6 and data[5] != 1:
            return None
        return {"incomplete": True}
    body = data[5:5 + rec_len]
    if len(body) < 4 or body[0] != 1:  # handshake type 1 = ClientHello
        return None
    hs_len = int.from_bytes(body[1:4], "big")
    p = body[4:4 + hs_len]

    try:
        version = _u16(p, 0)
        i = 2 + 32  # client_version + random
        sid_len = p[i]
        i += 1 + sid_len
        cs_len = _u16(p, i)
        i += 2
        ciphers = [_u16(p, i + k) for k in range(0, cs_len, 2)]
        i += cs_len
        comp_len = p[i]
        i += 1 + comp_len

        extensions: list[int] = []
        groups: list[int] = []
        point_formats: list[int] = []
        alpn: list[str] = []
        supported_versions: list[int] = []
        sni = None

        if i + 2 <= len(p):
            ext_total = _u16(p, i)
            i += 2
            end = min(len(p), i + ext_total)
            while i + 4 <= end:
                etype = _u16(p, i)
                elen = _u16(p, i + 2)
                edata = p[i + 4:i + 4 + elen]
                i += 4 + elen
                extensions.append(etype)
                if etype == 0 and len(edata) >= 5:  # server_name
                    name_len = _u16(edata, 3)
                    sni = edata[5:5 + name_len].decode("ascii", "replace").lower()
                elif etype == 10 and len(edata) >= 2:  # supported_groups
                    glen = _u16(edata, 0)
                    groups = [_u16(edata, 2 + k) for k in range(0, glen, 2)]
                elif etype == 11 and edata:  # ec_point_formats
                    point_formats = list(edata[1:1 + edata[0]])
                elif etype == 16 and len(edata) >= 2:  # ALPN
                    j = 2
                    while j < len(edata):
                        ln = edata[j]
                        alpn.append(edata[j + 1:j + 1 + ln].decode("ascii", "replace"))
                        j += 1 + ln
                elif etype == 43 and edata:  # supported_versions
                    vlen = edata[0]
                    supported_versions = [_u16(edata, 1 + k) for k in range(0, vlen, 2)]
    except (IndexError, ValueError):
        return None

    def join(values):
        return "-".join(str(v) for v in values if not is_grease(v))

    ja3_str = ",".join([
        str(version),
        join(ciphers),
        join(extensions),
        join(groups),
        join(point_formats),
    ])
    real_versions = [v for v in supported_versions if not is_grease(v)]
    max_version = max(real_versions) if real_versions else version

    return {
        "sni": sni,
        "version": max_version,
        "version_name": TLS_VERSIONS.get(max_version, hex(max_version)),
        "ja3": ja3_str,
        "ja3_hash": hashlib.md5(ja3_str.encode()).hexdigest(),
        "alpn": alpn,
        "cipher_count": len(ciphers),
    }
