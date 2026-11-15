"""Shared helpers: network scope, entropy, formatting, hashing."""

from __future__ import annotations

import hashlib
import ipaddress
import math
from collections import Counter
from datetime import datetime, timezone

DEFAULT_INTERNAL_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
]

# Public suffixes that take two labels (minimal list, good enough for triage).
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.kr", "com.br", "com.cn", "com.sa", "com.eg", "com.tr",
    "co.in", "co.za", "com.mx", "gov.sa", "edu.sa", "net.sa", "org.sa",
    "com.ae", "gov.ae", "co.il", "com.sg", "com.hk",
}


class NetScope:
    """Decides whether an IP belongs to the monitored (internal) network."""

    def __init__(self, cidrs: list[str] | None = None):
        self.cidrs = cidrs or DEFAULT_INTERNAL_CIDRS
        self.nets = [ipaddress.ip_network(c, strict=False) for c in self.cidrs]
        self._cache: dict[str, bool] = {}

    def is_internal(self, ip: str) -> bool:
        res = self._cache.get(ip)
        if res is None:
            try:
                addr = ipaddress.ip_address(ip)
                res = any(addr in n for n in self.nets if n.version == addr.version)
            except ValueError:
                res = False
            self._cache[ip] = res
        return res

    def is_external(self, ip: str) -> bool:
        return not self.is_internal(ip) and not is_special(ip)


def is_special(ip: str) -> bool:
    """Multicast / broadcast / unspecified addresses - not real peers."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return True
    return ip.endswith(".255") or ip == "255.255.255.255"


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def base_domain(name: str) -> str:
    """Return the registrable domain (example.co.uk / example.com)."""
    name = name.strip(".").lower()
    labels = name.split(".")
    if len(labels) <= 2:
        return name
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def sld_label(name: str) -> str:
    """Second-level label of a domain (the 'example' in example.com)."""
    return base_domain(name).split(".")[0]


def tld(name: str) -> str:
    return name.strip(".").lower().rsplit(".", 1)[-1]


def human_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024 or unit == "TB":
            return f"{num:,.0f} {unit}" if unit == "B" else f"{num:,.2f} {unit}"
        num /= 1024
    return f"{num:.2f} TB"


def fmt_ts(ts: float | None) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def file_hashes(path: str) -> dict[str, str]:
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def defang(value: str) -> str:
    """Defang an indicator for safe sharing in reports (evil[.]com)."""
    return value.replace(".", "[.]").replace("http", "hxxp")
