#!/usr/bin/env python3
"""Generate a synthetic PCAP containing benign traffic plus multiple attack
scenarios, for testing / demonstrating the NTI analyzer.

All malicious infrastructure uses RFC 5737 documentation IP ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and fictitious domains.

Usage:
    python tools/generate_sample_pcap.py -o samples/sample_incident.pcap
"""

from __future__ import annotations

import argparse
import base64
import os
import random
import string
import struct
from datetime import datetime, timezone

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap  # noqa: E402

rng = random.Random(1337)
PKTS = []

GW_MAC = "00:50:56:aa:00:01"
ATTACKER_MAC = "00:0c:29:de:ad:99"
DNS_SRV = "10.10.20.53"
WS_BENIGN = "10.10.20.15"
WS_PWNED = "10.10.20.23"
SCANNER = "10.10.20.66"
FILESRV = "10.10.20.5"

C2_IP, C2_DOMAIN = "203.0.113.66", "update-check-svc.top"
EXFIL_IP = "203.0.113.50"
ICMP_PEER = "198.51.100.77"
SHELL_IP = "198.51.100.44"
STAGER_IP, STAGER_HOST = "198.51.100.20", "files-cdn-dl.xyz"
TUNNEL_DOMAIN = "exfil-tunnel.xyz"

BENIGN_SITES = [
    ("www.google.com", "142.250.185.68"),
    ("login.microsoftonline.com", "20.190.151.7"),
    ("github.com", "140.82.121.4"),
    ("cdn.jsdelivr.net", "151.101.1.229"),
    ("www.wikipedia.org", "185.15.59.224"),
    ("outlook.office365.com", "52.97.146.34"),
]


def add(pkt, t):
    pkt.time = t
    PKTS.append(pkt)


def eth():
    return Ether(src="00:11:22:33:44:55", dst=GW_MAC)


# ------------------------------------------------------------------ DNS
def dns_exchange(client, qname, t, answer_ip=None, qtype="A", rcode=0, txt=None):
    sport = rng.randint(20000, 65000)
    qid = rng.randint(0, 65535)
    add(eth() / IP(src=client, dst=DNS_SRV) / UDP(sport=sport, dport=53) /
        DNS(id=qid, rd=1, qd=DNSQR(qname=qname, qtype=qtype)), t)
    an = None
    if rcode == 0:
        if txt is not None:
            an = DNSRR(rrname=qname, type="TXT", ttl=60, rdata=txt)
        elif answer_ip:
            an = DNSRR(rrname=qname, type="A", ttl=300, rdata=answer_ip)
    add(eth() / IP(src=DNS_SRV, dst=client) / UDP(sport=53, dport=sport) /
        DNS(id=qid, qr=1, aa=0, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=qname, qtype=qtype), an=an),
        t + rng.uniform(0.005, 0.04))


# ------------------------------------------------------------------ TLS
def _ext(etype, data):
    return struct.pack("!HH", etype, len(data)) + data


def client_hello(sni=None, ciphers=(0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8),
                 groups=(0x001D, 0x0017, 0x0018), grease=True):
    exts = b""
    if grease:
        exts += _ext(0x0A0A, b"")
    if sni:
        s = sni.encode()
        exts += _ext(0, struct.pack("!HBH", len(s) + 3, 0, len(s)) + s)
    exts += _ext(23, b"") + _ext(65281, b"\x00")
    exts += _ext(10, struct.pack("!H", len(groups) * 2) + b"".join(struct.pack("!H", g) for g in groups))
    exts += _ext(11, b"\x01\x00")
    alpn = b"\x02h2\x08http/1.1"
    exts += _ext(16, struct.pack("!H", len(alpn)) + alpn)
    exts += _ext(13, b"\x00\x08\x04\x03\x08\x04\x04\x01\x05\x03")
    exts += _ext(43, b"\x04\x03\x04\x03\x03")
    cs = ((0x2A2A,) if grease else ()) + tuple(ciphers)
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32) +
            struct.pack("!H", len(cs) * 2) + b"".join(struct.pack("!H", c) for c in cs) +
            b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def server_hello():
    body = b"\x03\x03" + os.urandom(32) + b"\x00\x13\x01\x00"
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def app_data(n):
    return b"\x17\x03\x03" + struct.pack("!H", n) + os.urandom(n)


# ------------------------------------------------------------------ TCP session
def tcp_session(client, server, dport, t, *, up=0, down=0, hello=None, raw_up=None, raw_down=None,
                chunk=1400, tls=True, ack_every=8):
    """Build a full TCP conversation. Returns end time."""
    sport = rng.randint(49152, 65000)
    cseq, sseq = rng.randint(1, 2**31), rng.randint(1, 2**31)
    rtt = rng.uniform(0.01, 0.06)
    C = lambda: eth() / IP(src=client, dst=server)  # noqa: E731
    S = lambda: eth() / IP(src=server, dst=client)  # noqa: E731
    add(C() / TCP(sport=sport, dport=dport, flags="S", seq=cseq), t)
    t += rtt
    add(S() / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1), t)
    cseq += 1
    sseq += 1
    t += 0.0005
    add(C() / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq), t)

    def send_c(data):
        nonlocal cseq, t
        t += 0.0008
        add(C() / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(data), t)
        cseq += len(data)

    def send_s(data):
        nonlocal sseq, t
        t += 0.0008
        add(S() / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(data), t)
        sseq += len(data)

    if tls:
        send_c(hello if hello is not None else client_hello())
        t += rtt
        send_s(server_hello() + app_data(rng.randint(2000, 3500)))
    if raw_up:
        send_c(raw_up)
    if raw_down:
        t += rtt
        send_s(raw_down)
    i = 0
    while up > 0:
        n = min(chunk, up)
        send_c(app_data(n) if tls else os.urandom(n))
        up -= n
        i += 1
        if i % ack_every == 0:
            add(S() / TCP(sport=dport, dport=sport, flags="A", seq=sseq, ack=cseq), t + 0.0002)
    i = 0
    while down > 0:
        n = min(chunk, down)
        send_s(app_data(n) if tls else os.urandom(n))
        down -= n
        i += 1
        if i % ack_every == 0:
            add(C() / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq), t + 0.0002)
    t += 0.01
    add(C() / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq), t)
    add(S() / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1), t + rtt)
    add(C() / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1), t + rtt + 0.0005)
    return t + rtt


def rand_label(n, alphabet=string.ascii_lowercase + string.digits):
    return "".join(rng.choice(alphabet) for _ in range(n))


# ================================================================== scenarios
def benign(t0, duration):
    for host in (WS_BENIGN, WS_PWNED, "10.10.20.31", "10.10.20.42"):
        t = t0 + rng.uniform(0, 20)
        while t < t0 + duration:
            name, ip = rng.choice(BENIGN_SITES)
            dns_exchange(host, name, t, ip)
            tcp_session(host, ip, 443, t + 0.05, up=rng.randint(800, 6000),
                        down=rng.randint(20_000, 250_000), hello=client_hello(name))
            t += rng.uniform(25, 90)


def beaconing(t0):
    dns_exchange(WS_PWNED, C2_DOMAIN, t0 + 30, C2_IP)
    hello = client_hello(C2_DOMAIN, ciphers=(0xC02F, 0xC030, 0x009C, 0x009D, 0x002F, 0x0035),
                         groups=(0x0017, 0x0018), grease=False)
    t = t0 + 31
    for _ in range(18):
        tcp_session(WS_PWNED, C2_IP, 443, t, up=rng.randint(300, 600), down=rng.randint(200, 400), hello=hello)
        t += 60 + rng.uniform(-0.8, 0.8)


def dga(t0):
    tlds = ["xyz", "top", "info", "biz", "net", "ru"]
    for i in range(40):
        name = rand_label(rng.randint(12, 18)) + "." + rng.choice(tlds)
        resolves = i in (17, 33)
        dns_exchange(WS_PWNED, name, t0 + i * 1.7, "203.0.113.99" if resolves else None,
                     rcode=0 if resolves else 3)


def dns_tunnel(t0):
    secret = os.urandom(3000)
    chunks = base64.b32encode(secret).decode().lower().rstrip("=")
    for i in range(0, min(len(chunks), 52 * 80), 52):
        q = f"{chunks[i:i + 52]}.{i // 52}.data.{TUNNEL_DOMAIN}"
        dns_exchange(WS_PWNED, q, t0 + i / 52 * 0.9, qtype="TXT", txt="ok")


def exfil(t0):
    # 6.5 MB over TLS to a raw IP (no SNI) on non-standard port 7443
    tcp_session(WS_PWNED, EXFIL_IP, 7443, t0, up=int(6.5 * 1024 * 1024), down=20_000,
                hello=client_hello(None, grease=False), ack_every=20)


def port_scan(t0):
    open_ports = {22, 80, 135, 139, 445, 3389}
    t = t0
    for port in range(1, 301):
        sport = rng.randint(40000, 60000)
        add(eth() / IP(src=SCANNER, dst=FILESRV) / TCP(sport=sport, dport=port, flags="S", seq=1000), t)
        if port in open_ports:
            add(eth() / IP(src=FILESRV, dst=SCANNER) / TCP(sport=port, dport=sport, flags="SA", seq=5000, ack=1001),
                t + 0.0004)
            add(eth() / IP(src=SCANNER, dst=FILESRV) / TCP(sport=sport, dport=port, flags="R", seq=1001), t + 0.0006)
        else:
            add(eth() / IP(src=FILESRV, dst=SCANNER) / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=1001),
                t + 0.0004)
        t += 0.004


def arp_spoof(t0):
    for i in range(6):
        add(Ether(src=GW_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, psrc="10.10.20.1", hwsrc=GW_MAC, pdst="10.10.20.255"), t0 + i * 30)
    for i in range(25):
        add(Ether(src=ATTACKER_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, psrc="10.10.20.1", hwsrc=ATTACKER_MAC, pdst=WS_BENIGN), t0 + 5 + i * 2)


def ftp_creds(t0):
    tcp_session(WS_BENIGN, FILESRV, 21, t0, tls=False, raw_down=b"220 FileZilla Server ready\r\n",
                raw_up=b"USER backup_admin\r\n")
    tcp_session(WS_BENIGN, FILESRV, 21, t0 + 1, tls=False, raw_up=b"PASS Winter2026!\r\n",
                raw_down=b"230 Logged on\r\n")


def icmp_tunnel(t0):
    for i in range(30):
        add(eth() / IP(src=WS_PWNED, dst=ICMP_PEER) / ICMP(type=8, id=0x4242, seq=i) / Raw(os.urandom(1000)),
            t0 + i * 2)
        add(eth() / IP(src=ICMP_PEER, dst=WS_PWNED) / ICMP(type=0, id=0x4242, seq=i) / Raw(os.urandom(1000)),
            t0 + i * 2 + 0.05)


def reverse_shell(t0):
    tcp_session(WS_PWNED, SHELL_IP, 4444, t0, tls=False, up=12_000, down=30_000,
                raw_down=b"Microsoft Windows [Version 10.0.19045]\r\nC:\\>")


def stager_download(t0):
    dns_exchange(WS_PWNED, STAGER_HOST, t0, STAGER_IP)
    req = (f"GET /payloads/update.ps1 HTTP/1.1\r\nHost: {STAGER_HOST}\r\n"
           "User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1\r\n"
           "Accept: */*\r\n\r\n").encode()
    tcp_session(WS_PWNED, STAGER_IP, 80, t0 + 0.1, tls=False, raw_up=req,
                raw_down=b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n", down=45_000)


def main():
    ap = argparse.ArgumentParser(description="Generate a synthetic incident PCAP")
    ap.add_argument("-o", "--output", default=os.path.join("samples", "sample_incident.pcap"))
    args = ap.parse_args()

    t0 = datetime(2026, 11, 14, 9, 0, 0, tzinfo=timezone.utc).timestamp()
    duration = 20 * 60
    benign(t0, duration)
    arp_spoof(t0 + 60)
    ftp_creds(t0 + 120)
    beaconing(t0)
    dga(t0 + 200)
    stager_download(t0 + 260)
    reverse_shell(t0 + 300)
    port_scan(t0 + 420)
    dns_tunnel(t0 + 540)
    icmp_tunnel(t0 + 700)
    exfil(t0 + 900)

    PKTS.sort(key=lambda p: p.time)
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    wrpcap(args.output, PKTS)
    print(f"[+] Wrote {len(PKTS):,} packets to {args.output}")


if __name__ == "__main__":
    main()

