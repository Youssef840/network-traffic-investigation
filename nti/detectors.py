"""Detection engine: turns collected traffic state into findings, IOCs and stats."""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field

from .collector import TrafficCollector
from .config import (ALLOWLIST_DOMAINS, MITRE, STANDARD_TLS_PORTS, SUSPICIOUS_PORTS,
                     SUSPICIOUS_TLDS, SUSPICIOUS_USER_AGENTS, ThreatIntel, Thresholds)
from .utils import (NetScope, base_domain, fmt_duration, human_bytes, shannon_entropy,
                    sld_label, tld)

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
SEVERITY_WEIGHT = {"Critical": 25, "High": 12, "Medium": 6, "Low": 2, "Info": 0}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    mitre: str = ""
    src: str = ""
    dst: str = ""
    indicators: list = field(default_factory=list)  # [(type, value), ...]
    evidence: list = field(default_factory=list)    # short strings
    count: int = 1
    first_seen: float | None = None
    last_seen: float | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["indicators"] = [{"type": t, "value": v} for t, v in self.indicators]
        return d


class Analyzer:
    def __init__(self, col: TrafficCollector, th: Thresholds, intel: ThreatIntel, scope: NetScope):
        self.col, self.th, self.intel, self.scope = col, th, intel, scope
        self.findings: list[Finding] = []

    # ================================================================ public
    def run(self) -> dict:
        self._dns_detections()
        self._tls_detections()
        self._intel_ip_matches()
        self._scan_detections()
        self._beacon_detections()
        self._exfil_detections()
        self._port_detections()
        self._icmp_detections()
        self._arp_detections()
        self._cleartext_detections()
        self._http_detections()
        self.findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], -f.count))
        return {
            "findings": [f.to_dict() for f in self.findings],
            "iocs": self._build_iocs(),
            "risk": self._risk(),
            "dns": self._dns_summary(),
            "tls": self._tls_summary(),
            "traffic": self._traffic_summary(),
        }

    def add(self, **kw) -> None:
        self.findings.append(Finding(**kw))

    def _domain_allowed(self, name: str) -> bool:
        bd = base_domain(name)
        return bd in ALLOWLIST_DOMAINS or tld(name) in ALLOWLIST_DOMAINS

    # =================================================================== DNS
    @staticmethod
    def _dga_score(label: str, th: Thresholds) -> tuple[bool, float]:
        if len(label) < th.dga_min_len:
            return False, 0.0
        ent = shannon_entropy(label)
        letters = [c for c in label if c.isalpha()]
        vowels = sum(1 for c in letters if c in "aeiou")
        vowel_ratio = vowels / len(letters) if letters else 0
        digit_ratio = sum(c.isdigit() for c in label) / len(label)
        is_dga = (
            ent >= th.dga_entropy
            or (ent >= th.dga_entropy_low_vowel and vowel_ratio < th.dga_vowel_ratio)
            or (digit_ratio >= 0.3 and ent >= 3.0)
        )
        return is_dga, ent

    def _dns_detections(self) -> None:
        th, col = self.th, self.col
        queries = col.dns_queries
        by_base: dict[str, list] = defaultdict(list)
        for q in queries:
            by_base[base_domain(q["qname"])].append(q)

        # 1) Threat-intel domain matches (queries + TLS SNI handled later)
        intel_hits: dict[str, list] = defaultdict(list)
        for q in queries:
            hit = self.intel.match_domain(q["qname"])
            if hit:
                intel_hits[q["qname"]].append(q)
        for name, qs in intel_hits.items():
            srcs = sorted({q["src"] for q in qs})
            self.add(severity="Critical", category="Threat Intel",
                     title=f"DNS lookup of blocklisted domain {name}",
                     description="An internal host resolved a domain present in the threat-intelligence blocklist.",
                     mitre=MITRE["intel"], src=", ".join(srcs), indicators=[("domain", name)],
                     evidence=[f"{len(qs)} queries from {', '.join(srcs)}"], count=len(qs),
                     first_seen=qs[0]["ts"], last_seen=qs[-1]["ts"])

        # 2) DGA-like domains, grouped per client
        dga_by_client: dict[str, dict] = defaultdict(dict)
        for q in queries:
            if self._domain_allowed(q["qname"]) or q["qtype"] == "PTR":
                continue
            is_dga, ent = self._dga_score(sld_label(q["qname"]), th)
            if is_dga:
                dga_by_client[q["src"]].setdefault(base_domain(q["qname"]), (ent, q["ts"]))
        nx_names = {r["qname"] for r in col.dns_responses if r["rcode"] == "NXDOMAIN"}
        for client, doms in dga_by_client.items():
            nx = sum(1 for d in doms if any(n.endswith(d) for n in nx_names))
            sev = "High" if len(doms) >= 5 or nx >= 3 else "Medium"
            top = sorted(doms.items(), key=lambda kv: -kv[1][0])
            self.add(severity=sev, category="DNS - DGA",
                     title=f"{len(doms)} DGA-like domain(s) queried by {client}",
                     description=("High-entropy, random-looking domain names are typical of malware using "
                                  "Domain Generation Algorithms to locate its C2 infrastructure."),
                     mitre=MITRE["dga"], src=client,
                     indicators=[("domain", d) for d, _ in top[:25]],
                     evidence=[f"{d} (entropy {e:.2f})" for d, (e, _) in top[:8]] + [f"{nx} of them returned NXDOMAIN"],
                     count=len(doms), first_seen=min(t for _, t in doms.values()),
                     last_seen=max(t for _, t in doms.values()))

        # 3) DNS tunneling per base domain
        for bd, qs in by_base.items():
            if self._domain_allowed(bd):
                continue
            subs = {q["qname"] for q in qs}
            avg_len = statistics.mean(len(q["qname"]) for q in qs)
            max_label = max(max(len(l) for l in q["qname"].split(".")) for q in qs)
            txt_null = sum(1 for q in qs if q["qtype"] in ("TXT", "NULL", "ANY"))
            reasons = []
            if len(subs) >= th.tunnel_unique_subdomains:
                reasons.append(f"{len(subs)} unique subdomains")
            if avg_len >= th.tunnel_avg_qname and len(qs) >= 10:
                reasons.append(f"avg query length {avg_len:.0f} chars")
            if txt_null >= 10 and txt_null / len(qs) > 0.5:
                reasons.append(f"{txt_null} TXT/NULL/ANY queries")
            if len(reasons) >= 2 or (reasons and max_label >= th.long_label):
                srcs = sorted({q["src"] for q in qs})
                self.add(severity="High", category="DNS - Tunneling",
                         title=f"Possible DNS tunneling via {bd}",
                         description=("Large numbers of long, unique subdomains under a single domain indicate data "
                                      "encoded inside DNS queries (C2 or exfiltration over DNS)."),
                         mitre=MITRE["dns_tunnel"], src=", ".join(srcs), indicators=[("domain", bd)],
                         evidence=reasons + [f"longest label {max_label} chars",
                                             f"sample: {sorted(subs, key=len)[-1][:90]}"],
                         count=len(qs), first_seen=qs[0]["ts"], last_seen=qs[-1]["ts"])
            elif max_label >= th.long_label or max(len(q["qname"]) for q in qs) >= th.long_qname:
                longest = max(subs, key=len)
                self.add(severity="Low", category="DNS - Anomalous Query",
                         title=f"Unusually long DNS query under {bd}",
                         description="Very long query names can carry encoded data.",
                         mitre=MITRE["dns_tunnel"], src=qs[0]["src"], indicators=[("domain", bd)],
                         evidence=[longest[:120]], count=len(qs), first_seen=qs[0]["ts"])

        # 4) NXDOMAIN storms per client
        resp_by_client: dict[str, Counter] = defaultdict(Counter)
        for r in col.dns_responses:
            resp_by_client[r["client"]][r["rcode"]] += 1
        for client, rc in resp_by_client.items():
            total, nx = sum(rc.values()), rc.get("NXDOMAIN", 0)
            if nx >= th.nxdomain_min and nx / total >= th.nxdomain_ratio:
                self.add(severity="Medium", category="DNS - NXDOMAIN",
                         title=f"High NXDOMAIN rate from {client}",
                         description="Many failed lookups suggest DGA activity or misconfigured malware.",
                         mitre=MITRE["dga"], src=client,
                         evidence=[f"{nx}/{total} responses NXDOMAIN ({nx / total:.0%})"], count=nx)

        # 5) Suspicious TLDs (not already reported above)
        reported = {v for f in self.findings for t, v in f.indicators if t == "domain"}
        tld_by_client: dict[str, dict] = defaultdict(dict)
        for bd, qs in by_base.items():
            if tld(bd) in SUSPICIOUS_TLDS and bd not in reported and not self._domain_allowed(bd):
                for q in qs:
                    tld_by_client[q["src"]].setdefault(bd, []).append(q["ts"])
        for client, doms in tld_by_client.items():
            ts_all = [t for v in doms.values() for t in v]
            self.add(severity="Low", category="DNS - Suspicious TLD",
                     title=f"{len(doms)} domain(s) in high-abuse TLDs queried by {client}",
                     description="TLDs such as .xyz/.top/.ru/.tk are disproportionately used for malicious infrastructure.",
                     mitre=MITRE["intel"], src=client, indicators=[("domain", d) for d in sorted(doms)],
                     evidence=[f"{d} ({len(v)} queries)" for d, v in sorted(doms.items())[:10]],
                     count=len(ts_all), first_seen=min(ts_all), last_seen=max(ts_all))

        # 6) Internal hosts using external resolvers directly
        ext_resolvers: dict[tuple, int] = Counter(
            (q["src"], q["server"]) for q in queries
            if self.scope.is_internal(q["src"]) and self.scope.is_external(q["server"]))
        for (src, server), n in ext_resolvers.items():
            if n >= 5:
                self.add(severity="Low", category="DNS - Resolver Bypass",
                         title=f"{src} queries external resolver {server} directly",
                         description="Bypassing the corporate resolver evades DNS logging and filtering.",
                         mitre=MITRE["dns_bypass"], src=src, dst=server,
                         indicators=[("ip", server)], count=n)

    # =================================================================== TLS
    def _tls_flows(self):
        return [f for f in self.col.flows.values()
                if f.proto == "TCP" and (f.tls or f.sport in STANDARD_TLS_PORTS)]

    def _tls_detections(self) -> None:
        no_sni: dict[str, list] = defaultdict(list)
        ja3_clients: dict[str, set] = defaultdict(set)
        sni_hits: dict[tuple, list] = defaultdict(list)
        ja3_hits: dict[tuple, list] = defaultdict(list)
        for f in self._tls_flows():
            if f.ja3_hash:
                ja3_clients[f.ja3_hash].add(f.client)
            if f.sni and self.intel.match_domain(f.sni):
                sni_hits[(f.client, f.sni, f.server, f.sport)].append(f)
            if f.ja3_hash and f.ja3_hash in self.intel.ja3:
                ja3_hits[(f.client, f.ja3_hash)].append(f)
            if f.hello_done and f.tls and not f.sni and self.scope.is_external(f.server):
                no_sni[f.server].append(f)
            if f.tls and f.sport not in STANDARD_TLS_PORTS:
                self.add(severity="Medium", category="TLS - Non-standard Port",
                         title=f"TLS on non-standard port {f.server}:{f.sport}",
                         description="Encrypted traffic on unusual ports is common for C2 and exfiltration channels.",
                         mitre=MITRE["nonstd_port"], src=f.client, dst=f"{f.server}:{f.sport}",
                         indicators=[("ip", f.server)],
                         evidence=[f"SNI: {f.sni or 'none'}", f"{human_bytes(f.total_bytes)} transferred"],
                         first_seen=f.first, last_seen=f.last)
            if f.tls_version in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
                self.add(severity="Low", category="TLS - Weak Protocol",
                         title=f"Deprecated {f.tls_version} offered by {f.client}",
                         description="Client advertises a deprecated TLS version (legacy or malicious tooling).",
                         mitre=MITRE["tls"], src=f.client, dst=f"{f.server}:{f.sport}",
                         indicators=[("ja3", f.ja3_hash)] if f.ja3_hash else [], first_seen=f.first)
        for (client, sni, server, port), flows in sni_hits.items():
            self.add(severity="Critical", category="Threat Intel",
                     title=f"TLS sessions to blocklisted domain {sni}",
                     description="TLS ClientHello SNI matches the threat-intelligence blocklist.",
                     mitre=MITRE["intel"], src=client, dst=f"{server}:{port}",
                     indicators=[("domain", sni), ("ip", server)]
                     + [("ja3", h) for h in {f.ja3_hash for f in flows if f.ja3_hash}],
                     evidence=[f"{len(flows)} session(s), {human_bytes(sum(f.total_bytes for f in flows))}",
                               f"JA3: {', '.join(sorted({f.ja3_hash for f in flows if f.ja3_hash}))}"],
                     count=len(flows), first_seen=min(f.first for f in flows),
                     last_seen=max(f.last for f in flows))
        for (client, h), flows in ja3_hits.items():
            self.add(severity="Critical", category="Threat Intel",
                     title=f"Malicious JA3 fingerprint ({self.intel.ja3[h]}) from {client}",
                     description="TLS client fingerprint matches a known malware family / tool.",
                     mitre=MITRE["tls"], src=client, dst=", ".join(sorted({f.server for f in flows}))[:60],
                     indicators=[("ja3", h)] + [("ip", s) for s in {f.server for f in flows}],
                     evidence=[f"{len(flows)} session(s)"], count=len(flows),
                     first_seen=min(f.first for f in flows))
        for server, flows in no_sni.items():
            self.add(severity="Medium", category="TLS - Missing SNI",
                     title=f"TLS sessions without SNI to {server}",
                     description=("Legitimate browsers always send SNI; direct-to-IP TLS is typical of malware "
                                  "and hard-coded C2 addresses."),
                     mitre=MITRE["tls"], src=", ".join(sorted({f.client for f in flows})), dst=server,
                     indicators=[("ip", server)] + [("ja3", h) for h in {f.ja3_hash for f in flows if f.ja3_hash}],
                     evidence=[f"{len(flows)} session(s), {human_bytes(sum(f.total_bytes for f in flows))}"],
                     count=len(flows), first_seen=min(f.first for f in flows))
        for h, clients in ja3_clients.items():
            if len(ja3_clients) >= 5 and len(clients) == 1:
                flows = [f for f in self._tls_flows() if f.ja3_hash == h]
                if len(flows) >= 5:
                    self.add(severity="Info", category="TLS - Rare JA3",
                             title=f"Rare JA3 fingerprint used only by {next(iter(clients))}",
                             description="A TLS fingerprint unique to one host may indicate non-browser software.",
                             mitre=MITRE["tls"], src=next(iter(clients)), indicators=[("ja3", h)],
                             evidence=[f"{len(flows)} sessions", f"servers: {', '.join(sorted({f.server for f in flows}))[:80]}"],
                             count=len(flows))

    def _intel_ip_matches(self) -> None:
        if not self.intel.ips:
            return
        hits: dict[str, list] = defaultdict(list)
        for f in self.col.flows.values():
            for ip in (f.server, f.client):
                if ip in self.intel.ips:
                    hits[ip].append(f)
        for ip, flows in hits.items():
            peers = sorted({f.client if f.server == ip else f.server for f in flows})
            self.add(severity="Critical", category="Threat Intel",
                     title=f"Communication with blocklisted IP {ip}",
                     description="Traffic observed to/from an IP address listed in threat intelligence.",
                     mitre=MITRE["intel"], src=", ".join(peers), dst=ip, indicators=[("ip", ip)],
                     evidence=[f"{len(flows)} flow(s), {human_bytes(sum(f.total_bytes for f in flows))}"],
                     count=len(flows), first_seen=min(f.first for f in flows),
                     last_seen=max(f.last for f in flows))

    # ============================================================ Scanning
    def _scan_detections(self) -> None:
        th = self.th
        vports: dict[tuple, set] = defaultdict(set)
        vopen: dict[tuple, set] = defaultdict(set)
        hhosts: dict[tuple, set] = defaultdict(set)
        syn_to: Counter = Counter()
        syn_unanswered: Counter = Counter()
        times: dict[tuple, list] = defaultdict(list)
        for f in self.col.flows.values():
            if f.proto != "TCP" or not f.syn:
                continue
            vports[(f.client, f.server)].add(f.sport)
            hhosts[(f.client, f.sport)].add(f.server)
            times[(f.client, f.server)].append(f.first)
            if f.synack:
                vopen[(f.client, f.server)].add(f.sport)
            syn_to[f.server] += 1
            if not f.synack:
                syn_unanswered[f.server] += 1
        for (src, dst), ports in vports.items():
            if len(ports) >= th.vscan_ports:
                t = times[(src, dst)]
                opened = sorted(vopen[(src, dst)])
                self.add(severity="High", category="Recon - Port Scan",
                         title=f"Vertical port scan: {src} -> {dst} ({len(ports)} ports)",
                         description="One host probed many TCP ports on a single target in a short time.",
                         mitre=MITRE["scan"], src=src, dst=dst, indicators=[("ip", src)],
                         evidence=[f"{len(ports)} ports probed in {fmt_duration(max(t) - min(t))}",
                                   f"open ports: {', '.join(map(str, opened[:20])) or 'none'}"],
                         count=len(ports), first_seen=min(t), last_seen=max(t))
        for (src, port), hosts in hhosts.items():
            if len(hosts) >= th.hscan_hosts:
                self.add(severity="Medium", category="Recon - Host Sweep",
                         title=f"Horizontal sweep on port {port} by {src} ({len(hosts)} hosts)",
                         description="One host connected to the same port on many different hosts.",
                         mitre=MITRE["scan"], src=src, indicators=[("ip", src)],
                         evidence=[", ".join(sorted(hosts)[:10])], count=len(hosts))
        for dst, n in syn_to.items():
            if n >= th.synflood_syns and syn_unanswered[dst] / n >= th.synflood_ratio:
                self.add(severity="High", category="DoS - SYN Flood",
                         title=f"Possible SYN flood against {dst}",
                         description="Large volume of half-open TCP connections.",
                         mitre=MITRE["flood"], dst=dst, indicators=[("ip", dst)],
                         evidence=[f"{n} SYNs, {syn_unanswered[dst]} unanswered"], count=n)

    # ============================================================ Beaconing
    def _beacon_detections(self) -> None:
        th = self.th
        conns: dict[tuple, list] = defaultdict(list)
        for f in self.col.flows.values():
            if f.proto == "TCP" and f.syn and self.scope.is_external(f.server):
                conns[(f.client, f.server, f.sport)].append(f)
        for (src, dst, port), flows in conns.items():
            if len(flows) < th.beacon_min_conns:
                continue
            ts = sorted(f.first for f in flows)
            gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
            if len(gaps) < th.beacon_min_conns - 1:
                continue
            mean = statistics.mean(gaps)
            cv = statistics.pstdev(gaps) / mean if mean else 1
            if mean >= th.beacon_min_interval and cv <= th.beacon_max_cv:
                snis = sorted({f.sni for f in flows if f.sni})
                names = snis or sorted(self.col.dns_ip_to_names.get(dst, []))
                inds = [("ip", dst)] + [("domain", n) for n in names]
                self.add(severity="High", category="C2 - Beaconing",
                         title=f"Periodic beaconing {src} -> {dst}:{port} every ~{mean:.1f}s",
                         description=("Connections at highly regular intervals are a hallmark of implants "
                                      "checking in with command-and-control servers."),
                         mitre=MITRE["beacon"], src=src, dst=f"{dst}:{port}", indicators=inds,
                         evidence=[f"{len(flows)} connections", f"mean interval {mean:.2f}s, jitter (CV) {cv:.3f}",
                                   f"domain(s): {', '.join(names) or 'n/a'}",
                                   f"avg session size {human_bytes(statistics.mean(f.total_bytes for f in flows))}"],
                         count=len(flows), first_seen=ts[0], last_seen=ts[-1])

    # ======================================================== Exfiltration
    def _exfil_detections(self) -> None:
        th = self.th
        pairs: dict[tuple, list] = defaultdict(list)
        for f in self.col.flows.values():
            if self.scope.is_internal(f.client) and self.scope.is_external(f.server):
                pairs[(f.client, f.server)].append(f)
        for (src, dst), flows in pairs.items():
            out = sum(f.bytes_out for f in flows)
            inn = sum(f.bytes_in for f in flows)
            ratio = out / inn if inn else float("inf")
            reason = None
            if out >= th.exfil_bytes:
                reason = f"{human_bytes(out)} uploaded (threshold {human_bytes(th.exfil_bytes)})"
            elif out >= th.exfil_ratio_min_bytes and ratio >= th.exfil_ratio:
                reason = f"asymmetric upload {human_bytes(out)} out vs {human_bytes(inn)} in"
            if reason:
                ports = sorted({f.sport for f in flows})
                names = sorted({f.sni for f in flows if f.sni} | self.col.dns_ip_to_names.get(dst, set()))
                self.add(severity="High", category="Exfiltration",
                         title=f"Large outbound transfer {src} -> {dst}",
                         description="Unusually high volume of data sent from an internal host to an external address.",
                         mitre=MITRE["exfil"], src=src, dst=dst,
                         indicators=[("ip", dst)] + [("domain", n) for n in names],
                         evidence=[reason, f"ports {ports}", f"out/in ratio {ratio:.1f}" if inn else "no inbound data",
                                   f"duration {fmt_duration(max(f.last for f in flows) - min(f.first for f in flows))}"],
                         count=len(flows), first_seen=min(f.first for f in flows),
                         last_seen=max(f.last for f in flows))

    # ====================================================== Port anomalies
    def _port_detections(self) -> None:
        seen = set()
        for f in self.col.flows.values():
            if f.sport in SUSPICIOUS_PORTS and self.scope.is_external(f.server) and (f.pkts_in or f.synack):
                key = (f.client, f.server, f.sport)
                if key in seen:
                    continue
                seen.add(key)
                self.add(severity="High", category="Suspicious Port",
                         title=f"Connection to {f.server}:{f.sport} ({SUSPICIOUS_PORTS[f.sport]})",
                         description="Outbound connection to a port strongly associated with backdoors, RATs or C2.",
                         mitre=MITRE["nonstd_port"], src=f.client, dst=f"{f.server}:{f.sport}",
                         indicators=[("ip", f.server)],
                         evidence=[f"{human_bytes(f.total_bytes)}, {f.pkts_out + f.pkts_in} packets",
                                   f"duration {fmt_duration(f.duration)}"],
                         first_seen=f.first, last_seen=f.last)

    # ================================================================= ICMP
    def _icmp_detections(self) -> None:
        th = self.th
        for (src, dst), st in self.col.icmp_stats.items():
            avg = st["bytes"] / st["count"] if st["count"] else 0
            if st["count"] >= th.icmp_min_packets and avg >= th.icmp_payload_avg:
                self.add(severity="Medium", category="ICMP Tunneling",
                         title=f"Large ICMP payloads {src} -> {dst}",
                         description="ICMP echo packets carrying large payloads can be used to tunnel data.",
                         mitre=MITRE["icmp"], src=src, dst=dst, indicators=[("ip", dst)],
                         evidence=[f"{st['count']} packets, avg payload {avg:.0f} B, max {st['max']} B"],
                         count=st["count"])

    # ================================================================== ARP
    def _arp_detections(self) -> None:
        for ip, macs in self.col.arp_bindings.items():
            if len(macs) > 1:
                self.add(severity="High", category="ARP Spoofing",
                         title=f"IP {ip} claimed by {len(macs)} MAC addresses",
                         description="Conflicting ARP replies indicate ARP cache poisoning (man-in-the-middle).",
                         mitre=MITRE["arp"], dst=ip,
                         indicators=[("mac", m) for m in sorted(macs)],
                         evidence=[f"MACs: {', '.join(sorted(macs))}", f"{self.col.arp_replies[ip]} ARP replies"],
                         count=len(macs))

    # ============================================================ Cleartext
    def _cleartext_detections(self) -> None:
        grouped: dict[tuple, list] = defaultdict(list)
        for c in self.col.cleartext_creds:
            grouped[(c["src"], c["dst"], c["protocol"])].append(c)
        for (src, dst, proto), items in grouped.items():
            self.add(severity="High", category="Cleartext Credentials",
                     title=f"{proto} credentials sent in cleartext {src} -> {dst}",
                     description="Authentication data was transmitted without encryption and can be sniffed.",
                     mitre=MITRE["cleartext"], src=src, dst=f"{dst}:{items[0]['dport']}",
                     evidence=[f"{c['command']} {c['value']}" for c in items[:6]],
                     count=len(items), first_seen=items[0]["ts"])

    # ================================================================= HTTP
    def _http_detections(self) -> None:
        for r in self.col.http_requests:
            ua = r["user_agent"].lower()
            uri = r["uri"].lower()
            hits = [s for s in SUSPICIOUS_USER_AGENTS if s in ua]
            risky_file = any(uri.split("?")[0].endswith(ext) for ext in
                             (".exe", ".dll", ".ps1", ".bat", ".hta", ".vbs", ".scr", ".bin", ".sh", ".jar"))
            if hits or risky_file:
                host = r["host"] or r["dst"]
                sev = "High" if hits and risky_file else "Medium"
                self.add(severity=sev, category="HTTP - Suspicious Request",
                         title=f"{r['method']} {host}{r['uri'][:60]}",
                         description=("Scripted user-agent and/or download of an executable/script over cleartext "
                                      "HTTP - common in malware staging."),
                         mitre=MITRE["ua"], src=r["src"], dst=f"{r['dst']}:{r['dport']}",
                         indicators=[("url", f"http://{host}{r['uri']}"), ("ip", r["dst"])]
                         + ([("user_agent", r["user_agent"])] if hits else []),
                         evidence=[f"User-Agent: {r['user_agent'] or '-'}"], first_seen=r["ts"])

    # ============================================================ summaries
    def _build_iocs(self) -> list[dict]:
        iocs: dict[tuple, dict] = {}
        for f in self.findings:
            for itype, value in f.indicators:
                if not value:
                    continue
                if itype == "ip" and self.scope.is_internal(value) and f.category not in ("Recon - Port Scan",):
                    continue
                key = (itype, value)
                entry = iocs.setdefault(key, {"type": itype, "value": value, "severity": f.severity,
                                              "categories": set(), "hits": 0, "first_seen": f.first_seen})
                if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[entry["severity"]]:
                    entry["severity"] = f.severity
                entry["categories"].add(f.category)
                entry["hits"] += f.count
                if f.first_seen and (not entry["first_seen"] or f.first_seen < entry["first_seen"]):
                    entry["first_seen"] = f.first_seen
        out = []
        for e in iocs.values():
            e["categories"] = sorted(e["categories"])
            if e["type"] == "ip":
                e["context"] = ", ".join(sorted(self.col.dns_ip_to_names.get(e["value"], [])))[:80]
            else:
                e["context"] = ""
            out.append(e)
        out.sort(key=lambda e: (-SEVERITY_ORDER[e["severity"]], e["type"], e["value"]))
        return out

    def _risk(self) -> dict:
        counts = Counter(f.severity for f in self.findings)
        score = min(100, sum(SEVERITY_WEIGHT[s] * n for s, n in counts.items()))
        if counts.get("Critical") and score < 70:
            score = max(score, 70)
        level = ("Critical" if score >= 70 else "High" if score >= 40 else
                 "Medium" if score >= 15 else "Low" if score > 0 else "Clean")
        return {"score": score, "level": level,
                "by_severity": {s: counts.get(s, 0) for s in SEVERITY_ORDER},
                "by_category": dict(Counter(f.category for f in self.findings).most_common())}

    def _dns_summary(self) -> dict:
        q, r = self.col.dns_queries, self.col.dns_responses
        bases = Counter(base_domain(x["qname"]) for x in q)
        return {
            "total_queries": len(q),
            "total_responses": len(r),
            "unique_names": len({x["qname"] for x in q}),
            "unique_base_domains": len(bases),
            "top_domains": bases.most_common(15),
            "qtypes": Counter(x["qtype"] for x in q).most_common(),
            "rcodes": Counter(x["rcode"] for x in r).most_common(),
            "top_clients": Counter(x["src"] for x in q).most_common(10),
            "resolvers": Counter(x["server"] for x in q).most_common(5),
        }

    def _tls_summary(self) -> dict:
        servers: dict[str, dict] = {}
        clients: dict[str, dict] = {}
        ja3: Counter = Counter()
        versions: Counter = Counter()
        flows = self._tls_flows()
        for f in flows:
            s = servers.setdefault(f.server, {"ip": f.server, "sessions": 0, "bytes_out": 0, "bytes_in": 0,
                                              "ports": set(), "sni": set(), "clients": set(), "ja3": set(),
                                              "first": f.first, "last": f.last})
            s["sessions"] += 1
            s["bytes_out"] += f.bytes_out
            s["bytes_in"] += f.bytes_in
            s["ports"].add(f.sport)
            s["clients"].add(f.client)
            s["first"], s["last"] = min(s["first"], f.first), max(s["last"], f.last)
            if f.sni:
                s["sni"].add(f.sni)
            if f.ja3_hash:
                s["ja3"].add(f.ja3_hash)
                ja3[f.ja3_hash] += 1
            if f.tls_version:
                versions[f.tls_version] += 1
            c = clients.setdefault(f.client, {"ip": f.client, "sessions": 0, "bytes_out": 0,
                                              "bytes_in": 0, "servers": set()})
            c["sessions"] += 1
            c["bytes_out"] += f.bytes_out
            c["bytes_in"] += f.bytes_in
            c["servers"].add(f.server)

        def finalize(d: dict) -> dict:
            out = {}
            for k, v in d.items():
                out[k] = sorted(v) if isinstance(v, set) else v
            out["total"] = d["bytes_out"] + d["bytes_in"]
            return out

        server_rows = []
        for s in servers.values():
            row = finalize(s)
            row["dns_names"] = sorted(self.col.dns_ip_to_names.get(s["ip"], []))
            server_rows.append(row)
        server_rows.sort(key=lambda x: -x["total"])
        client_rows = sorted((finalize(c) for c in clients.values()), key=lambda x: -x["total"])
        for c in client_rows:
            c["servers"] = len(c["servers"])
        return {
            "sessions": len(flows),
            "handshakes_parsed": sum(1 for f in flows if f.ja3_hash),
            "total_bytes": sum(f.total_bytes for f in flows),
            "servers": server_rows,
            "clients": client_rows,
            "ja3_top": ja3.most_common(10),
            "versions": versions.most_common(),
            "unique_sni": len({f.sni for f in flows if f.sni}),
        }

    def _traffic_summary(self) -> dict:
        col = self.col
        talkers = Counter()
        for ip in set(col.ip_sent) | set(col.ip_recv):
            talkers[ip] = col.ip_sent[ip] + col.ip_recv[ip]
        conv = Counter()
        for f in col.flows.values():
            conv[(f.client, f.server, f.proto, f.sport)] += f.total_bytes
        dports = Counter(f"{f.proto}/{f.sport}" for f in col.flows.values())
        # timeline: rebucket into <= 60 bins
        timeline = []
        if col.per_second:
            start, end = min(col.per_second), max(col.per_second)
            span = max(1, end - start + 1)
            width = max(1, -(-span // 60))
            bins = Counter()
            for sec, n in col.per_second.items():
                bins[(sec - start) // width] += n
            timeline = [(start + i * width, bins.get(i, 0)) for i in range((span + width - 1) // width)]
        return {
            "protocols": col.protocols.most_common(),
            "top_talkers": [{"ip": ip, "bytes": b, "sent": col.ip_sent[ip], "recv": col.ip_recv[ip],
                             "internal": self.scope.is_internal(ip)} for ip, b in talkers.most_common(15)],
            "top_conversations": [{"client": c, "server": s, "proto": p, "port": port, "bytes": b}
                                  for (c, s, p, port), b in conv.most_common(15)],
            "top_services": dports.most_common(15),
            "unique_ips": len(talkers),
            "internal_hosts": sum(1 for ip in talkers if self.scope.is_internal(ip)),
            "external_hosts": sum(1 for ip in talkers if self.scope.is_external(ip)),
            "flows": len(col.flows),
            "http_requests": len(col.http_requests),
            "timeline": timeline,
            "bucket_seconds": timeline[1][0] - timeline[0][0] if len(timeline) > 1 else 1,
        }
