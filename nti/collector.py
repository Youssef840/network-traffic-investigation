"""Single-pass packet collector.

Streams packets from one or more PCAP/PCAPNG files and builds the state that
detectors and reports work from: flows, DNS transactions, TLS handshakes,
HTTP requests, ARP bindings, ICMP payload stats and per-IP volumes.
"""

from __future__ import annotations

import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, IPv6, PcapReader  # noqa: F401
from scapy.layers.inet6 import ICMPv6EchoRequest  # noqa: F401

from .tls import CT_APPDATA, CT_HANDSHAKE, parse_client_hello, tls_record_info

SYN, ACK, RST, FIN = 0x02, 0x10, 0x04, 0x01

QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
CLEARTEXT_AUTH_PORTS = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 25: "SMTP", 587: "SMTP"}


@dataclass
class Flow:
    proto: str
    client: str
    cport: int
    server: str
    sport: int
    first: float
    last: float
    pkts_out: int = 0
    pkts_in: int = 0
    bytes_out: int = 0          # client -> server (wire bytes)
    bytes_in: int = 0           # server -> client
    syn: bool = False
    synack: bool = False
    rst: bool = False
    fin: bool = False
    tls: bool = False
    sni: str | None = None
    ja3: str | None = None
    ja3_hash: str | None = None
    tls_version: str | None = None
    alpn: list = field(default_factory=list)
    hello_done: bool = False
    client_buf: bytearray | None = None

    @property
    def total_bytes(self) -> int:
        return self.bytes_out + self.bytes_in

    @property
    def duration(self) -> float:
        return self.last - self.first


class TrafficCollector:
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.files: list[str] = []
        self.total_packets = 0
        self.total_bytes = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.protocols: Counter = Counter()
        self.ip_sent: Counter = Counter()
        self.ip_recv: Counter = Counter()
        self.ip_pkts: Counter = Counter()
        self.per_second: Counter = Counter()
        self.flows: dict[tuple, Flow] = {}
        # DNS
        self.dns_queries: list[dict] = []
        self.dns_responses: list[dict] = []
        self.dns_ip_to_names: dict[str, set] = defaultdict(set)
        # Application layer
        self.http_requests: list[dict] = []
        self.cleartext_creds: list[dict] = []
        # L2 / ICMP
        self.arp_bindings: dict[str, set] = defaultdict(set)
        self.arp_replies: Counter = Counter()
        self.icmp_stats: dict[tuple, dict] = {}
        self.errors = 0

    # ------------------------------------------------------------------ input
    def load(self, path: str, max_packets: int | None = None) -> None:
        self.files.append(path)
        count = 0
        with PcapReader(path) as reader:
            for pkt in reader:
                try:
                    self.process(pkt)
                except Exception:  # malformed packet - never abort the run
                    self.errors += 1
                count += 1
                if self.verbose and count % 50000 == 0:
                    print(f"    ... {count:,} packets processed", file=sys.stderr)
                if max_packets and count >= max_packets:
                    break

    # ------------------------------------------------------------- dispatch
    def process(self, pkt) -> None:
        ts = float(pkt.time)
        wire = len(pkt)
        self.total_packets += 1
        self.total_bytes += wire
        if self.first_ts is None or ts < self.first_ts:
            self.first_ts = ts
        if self.last_ts is None or ts > self.last_ts:
            self.last_ts = ts
        self.per_second[int(ts)] += 1

        if pkt.haslayer(ARP):
            self.protocols["ARP"] += 1
            arp = pkt[ARP]
            if arp.op == 2:  # is-at
                self.arp_bindings[arp.psrc].add(arp.hwsrc.lower())
                self.arp_replies[arp.psrc] += 1
            return

        if pkt.haslayer(IP):
            ip = pkt[IP]
            src, dst = ip.src, ip.dst
        elif pkt.haslayer(IPv6):
            ip = pkt[IPv6]
            src, dst = ip.src, ip.dst
        else:
            self.protocols["Other-L2"] += 1
            return

        self.ip_sent[src] += wire
        self.ip_recv[dst] += wire
        self.ip_pkts[src] += 1
        self.ip_pkts[dst] += 1

        if pkt.haslayer(TCP):
            self._tcp(pkt, ts, wire, src, dst)
        elif pkt.haslayer(UDP):
            self._udp(pkt, ts, wire, src, dst)
        elif pkt.haslayer(ICMP) or getattr(ip, "nh", None) == 58:
            self.protocols["ICMP"] += 1
            self._icmp(pkt, src, dst)
        else:
            self.protocols["Other-IP"] += 1

    # ------------------------------------------------------------------ flows
    def _get_flow(self, proto, src, sport, dst, dport, ts, client_hint):
        a, b = (src, sport), (dst, dport)
        key = (proto,) + (a + b if a <= b else b + a)
        flow = self.flows.get(key)
        if flow is None:
            if client_hint == "src":
                c, cp, s, sp = src, sport, dst, dport
            elif client_hint == "dst":
                c, cp, s, sp = dst, dport, src, sport
            elif sport < dport:  # heuristic: lower port is the service
                c, cp, s, sp = dst, dport, src, sport
            else:
                c, cp, s, sp = src, sport, dst, dport
            flow = Flow(proto, c, cp, s, sp, ts, ts)
            self.flows[key] = flow
        return flow

    def _account(self, flow: Flow, src, sport, ts, wire) -> bool:
        outbound = src == flow.client and sport == flow.cport
        if outbound:
            flow.pkts_out += 1
            flow.bytes_out += wire
        else:
            flow.pkts_in += 1
            flow.bytes_in += wire
        flow.last = max(flow.last, ts)
        flow.first = min(flow.first, ts)
        return outbound

    # -------------------------------------------------------------------- TCP
    def _tcp(self, pkt, ts, wire, src, dst):
        tcp = pkt[TCP]
        sport, dport = int(tcp.sport), int(tcp.dport)
        flags = int(tcp.flags)
        hint = None
        if flags & SYN and not flags & ACK:
            hint = "src"
        elif flags & SYN and flags & ACK:
            hint = "dst"
        flow = self._get_flow("TCP", src, sport, dst, dport, ts, hint)
        outbound = self._account(flow, src, sport, ts, wire)

        if flags & SYN and not flags & ACK:
            flow.syn = True
        if flags & SYN and flags & ACK:
            flow.synack = True
        if flags & RST:
            flow.rst = True
        if flags & FIN:
            flow.fin = True

        payload = bytes(tcp.payload)
        if not payload:
            self.protocols["TCP"] += 1
            return

        if outbound:
            self._client_payload(flow, payload, ts)
        else:
            rec = tls_record_info(payload)
            if rec and rec[0] in (CT_HANDSHAKE, CT_APPDATA):
                flow.tls = True
        self.protocols["TLS" if flow.tls else "TCP"] += 1

    def _client_payload(self, flow: Flow, payload: bytes, ts: float):
        # TLS ClientHello (may span several segments)
        if not flow.hello_done and (flow.client_buf is not None or payload[:1] == b"\x16"):
            buf = (flow.client_buf or bytearray()) + payload
            res = parse_client_hello(bytes(buf))
            if res is None:
                flow.hello_done, flow.client_buf = True, None
            elif res.get("incomplete"):
                if len(buf) < 16384:
                    flow.client_buf = buf
                else:
                    flow.hello_done, flow.client_buf = True, None
            else:
                flow.hello_done, flow.client_buf, flow.tls = True, None, True
                flow.sni = res["sni"]
                flow.ja3, flow.ja3_hash = res["ja3"], res["ja3_hash"]
                flow.tls_version = res["version_name"]
                flow.alpn = res["alpn"]
            return
        rec = tls_record_info(payload)
        if rec and rec[0] == CT_APPDATA:
            flow.tls = True
            return

        # Cleartext HTTP
        if payload.startswith(HTTP_METHODS):
            self._http(flow, payload, ts)
            return

        # Cleartext authentication (FTP/POP3/IMAP/Telnet/SMTP)
        proto = CLEARTEXT_AUTH_PORTS.get(flow.sport)
        if proto:
            line = payload[:200].decode("latin-1", "replace").strip()
            upper = line.upper()
            for kw in ("USER ", "PASS ", "LOGIN ", "AUTH PLAIN ", "AUTH LOGIN"):
                if upper.startswith(kw) or (kw == "LOGIN " and " LOGIN " in upper[:20]):
                    value = line.split(" ", 1)[1] if " " in line else ""
                    self.cleartext_creds.append({
                        "ts": ts, "src": flow.client, "dst": flow.server, "dport": flow.sport,
                        "protocol": proto, "command": kw.strip(),
                        "value": value if kw.startswith("USER") else _mask(value),
                    })
                    break

    def _http(self, flow: Flow, payload: bytes, ts: float):
        text = payload[:4096].decode("latin-1", "replace")
        lines = text.split("\r\n")
        parts = lines[0].split(" ")
        headers = {}
        for ln in lines[1:]:
            if not ln:
                break
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        req = {
            "ts": ts, "src": flow.client, "dst": flow.server, "dport": flow.sport,
            "method": parts[0], "uri": parts[1] if len(parts) > 1 else "",
            "host": headers.get("host", ""), "user_agent": headers.get("user-agent", ""),
        }
        self.http_requests.append(req)
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            self.cleartext_creds.append({
                "ts": ts, "src": flow.client, "dst": flow.server, "dport": flow.sport,
                "protocol": "HTTP", "command": "Authorization: Basic", "value": _mask(auth[6:]),
            })

    # -------------------------------------------------------------------- UDP
    def _udp(self, pkt, ts, wire, src, dst):
        udp = pkt[UDP]
        sport, dport = int(udp.sport), int(udp.dport)
        hint = None
        if dport in (53, 5353, 123, 443, 67, 137, 161, 500, 1900):
            hint = "src"
        elif sport in (53, 5353, 123, 443, 67, 137, 161, 500, 1900):
            hint = "dst"
        flow = self._get_flow("UDP", src, sport, dst, dport, ts, hint)
        self._account(flow, src, sport, ts, wire)

        if pkt.haslayer(DNS) and (sport in (53, 5353) or dport in (53, 5353)):
            self.protocols["DNS"] += 1
            self._dns(pkt[DNS], ts, src, dst)
        elif 443 in (sport, dport):
            self.protocols["QUIC"] += 1
        else:
            self.protocols["UDP"] += 1

    def _dns(self, dns, ts, src, dst):
        q = _first(dns.qd, dns.qdcount)
        if q is None:
            return
        qname = _decode(q.qname).rstrip(".").lower()
        qtype = QTYPES.get(int(q.qtype), str(q.qtype))
        if dns.qr == 0:
            self.dns_queries.append({"ts": ts, "src": src, "server": dst, "qname": qname, "qtype": qtype})
            return
        answers = []
        for rr in _iter_rr(dns.an, dns.ancount):
            rtype = int(getattr(rr, "type", 0))
            rdata = rr.rdata
            if isinstance(rdata, (list, tuple)):
                rdata = b" ".join(x if isinstance(x, bytes) else str(x).encode() for x in rdata)
            value = _decode(rdata)
            answers.append({"type": QTYPES.get(rtype, str(rtype)), "value": value})
            if rtype in (1, 28):
                self.dns_ip_to_names[value].add(qname)
        self.dns_responses.append({
            "ts": ts, "client": dst, "server": src, "qname": qname, "qtype": qtype,
            "rcode": RCODES.get(int(dns.rcode), str(dns.rcode)), "answers": answers,
        })

    # ------------------------------------------------------------------- ICMP
    def _icmp(self, pkt, src, dst):
        payload = b""
        if pkt.haslayer(ICMP):
            payload = bytes(pkt[ICMP].payload)
        key = (src, dst)
        st = self.icmp_stats.setdefault(key, {"count": 0, "bytes": 0, "max": 0})
        st["count"] += 1
        st["bytes"] += len(payload)
        st["max"] = max(st["max"], len(payload))


# ---------------------------------------------------------------- helpers
def _decode(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


def _first(field_value, count):
    if field_value is None:
        return None
    if isinstance(field_value, list):
        return field_value[0] if field_value else None
    try:
        return field_value[0]
    except (IndexError, TypeError):
        return field_value


def _iter_rr(field_value, count):
    """Iterate DNS resource records across Scapy versions (list or chained)."""
    if field_value is None:
        return
    if isinstance(field_value, list):
        yield from field_value
        return
    for i in range(int(count or 0)):
        try:
            yield field_value[i]
        except IndexError:
            break
