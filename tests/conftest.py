"""Shared fixtures. The full sample capture is generated once per test session."""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make_client_hello(sni: str = "example.com", ciphers=(0x1301, 0x1302, 0xC02F), grease: bool = True) -> bytes:
    """Build a minimal but valid TLS 1.2 record carrying a ClientHello."""
    cs = ([0x0A0A] if grease else []) + list(ciphers)
    host = sni.encode()
    sni_ext = struct.pack("!HBH", len(host) + 3, 0, len(host)) + host
    groups = struct.pack("!H", 4) + struct.pack("!HH", 0x001D, 0x0017)
    exts = (struct.pack("!HH", 0, len(sni_ext)) + sni_ext
            + struct.pack("!HH", 10, len(groups)) + groups
            + struct.pack("!HH", 11, 2) + bytes([1, 0]))
    body = (struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00"
            + struct.pack("!H", len(cs) * 2) + b"".join(struct.pack("!H", c) for c in cs)
            + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


@pytest.fixture(scope="session")
def sample_pcap(tmp_path_factory) -> str:
    out = tmp_path_factory.mktemp("pcap") / "sample.pcap"
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "generate_sample_pcap.py"), "-o", str(out)],
                   check=True, capture_output=True)
    return str(out)


@pytest.fixture(scope="session")
def analysis(sample_pcap, tmp_path_factory):
    """Run the full CLI once; returns (output_dir, results_dict)."""
    from nti.cli import main

    out = tmp_path_factory.mktemp("out")
    rc = main([sample_pcap, "-o", str(out), "--case-id", "TEST-001", "-q"])
    assert rc == 0
    with open(out / "TEST-001_results.json", encoding="utf-8") as fh:
        return out, json.load(fh)
