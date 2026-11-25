"""Detection thresholds, allowlists and threat-intel loading."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field


@dataclass
class Thresholds:
    # --- DNS ---
    dga_min_len: int = 10              # min length of 2nd-level label to test for DGA
    dga_entropy: float = 3.5           # entropy that alone marks a label as DGA-like
    dga_entropy_low_vowel: float = 3.1 # entropy when combined with low vowel ratio
    dga_vowel_ratio: float = 0.22
    long_qname: int = 60               # characters
    long_label: int = 40               # characters
    tunnel_unique_subdomains: int = 30 # unique subdomains under one base domain
    tunnel_avg_qname: int = 45         # average qname length under one base domain
    nxdomain_min: int = 15             # NXDOMAIN responses per client
    nxdomain_ratio: float = 0.30
    # --- Scanning / flooding ---
    vscan_ports: int = 20              # distinct dst ports on one host
    hscan_hosts: int = 20              # distinct hosts on one port
    synflood_syns: int = 500
    synflood_ratio: float = 0.8
    # --- Beaconing ---
    beacon_min_conns: int = 8
    beacon_max_cv: float = 0.15        # coefficient of variation of intervals
    beacon_min_interval: float = 1.0   # seconds
    # --- Exfiltration ---
    exfil_bytes: int = 5 * 1024 * 1024
    exfil_ratio: float = 10.0          # out/in ratio for "asymmetric upload"
    exfil_ratio_min_bytes: int = 1 * 1024 * 1024
    # --- ICMP ---
    icmp_payload_avg: int = 128
    icmp_min_packets: int = 10


STANDARD_TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 5061, 8443}

SUSPICIOUS_PORTS = {
    4444: "Metasploit default handler",
    1337: "Common backdoor / leet port",
    31337: "Back Orifice / elite backdoor",
    6666: "IRC / botnet C2",
    6667: "IRC / botnet C2",
    6697: "IRC over TLS / botnet C2",
    5555: "Android ADB / RAT",
    12345: "NetBus trojan",
    9001: "Tor relay (ORPort)",
    9030: "Tor directory",
    3389: "RDP exposed to Internet",
    23: "Telnet to Internet",
    445: "SMB to Internet",
    5900: "VNC to Internet",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "su", "ru",
    "zip", "mov", "click", "country", "kim", "work", "loan", "gdn",
    "racing", "rest", "bid", "icu", "cyou", "monster", "onion",
}

SUSPICIOUS_USER_AGENTS = [
    "python-requests", "python-urllib", "curl/", "wget/", "powershell",
    "windowspowershell", "go-http-client", "nmap", "sqlmap", "nikto",
    "masscan", "zgrab", "certutil", "bitsadmin", "winhttp",
]

# Popular domains excluded from DGA / tunneling heuristics to reduce noise.
ALLOWLIST_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "youtube.com", "ytimg.com", "microsoft.com", "microsoftonline.com",
    "windows.com", "windowsupdate.com", "office.com", "office365.com",
    "live.com", "msn.com", "bing.com", "azure.com", "azureedge.net",
    "msftconnecttest.com", "apple.com", "icloud.com", "amazon.com",
    "amazonaws.com", "cloudfront.net", "akamaiedge.net", "akamai.net",
    "akamaihd.net", "cloudflare.com", "cloudflare-dns.com", "github.com",
    "githubusercontent.com", "facebook.com", "fbcdn.net", "whatsapp.net",
    "mozilla.org", "mozilla.net", "digicert.com", "letsencrypt.org",
    "jsdelivr.net", "ubuntu.com", "debian.org", "in-addr.arpa", "ip6.arpa",
    "local", "localdomain", "lan",
}

MITRE = {
    "dga": "T1568.002 Dynamic Resolution: DGA",
    "dns_tunnel": "T1071.004 App Layer Protocol: DNS",
    "beacon": "T1071.001 Web Protocols / T1573 Encrypted Channel",
    "scan": "T1046 Network Service Discovery",
    "exfil": "T1041 Exfiltration Over C2 Channel / T1048",
    "nonstd_port": "T1571 Non-Standard Port",
    "arp": "T1557.002 ARP Cache Poisoning",
    "cleartext": "T1040 Network Sniffing / T1552 Unsecured Credentials",
    "icmp": "T1095 Non-Application Layer Protocol",
    "intel": "T1071 Application Layer Protocol",
    "ua": "T1105 Ingress Tool Transfer",
    "tls": "T1573.002 Encrypted Channel: Asymmetric Crypto",
    "flood": "T1498 Network Denial of Service",
    "dns_bypass": "T1071.004 App Layer Protocol: DNS",
}


@dataclass
class ThreatIntel:
    domains: set = field(default_factory=set)
    ips: set = field(default_factory=set)
    ja3: dict = field(default_factory=dict)  # hash -> label

    @classmethod
    def load(cls, directory: str | None) -> ThreatIntel:
        intel = cls()
        if not directory or not os.path.isdir(directory):
            return intel

        def lines(fname):
            path = os.path.join(directory, fname)
            if not os.path.exists(path):
                return []
            with open(path, encoding="utf-8") as fh:
                return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]

        intel.domains = {d.lower().strip(".") for d in lines("malicious_domains.txt")}
        intel.ips = set(lines("malicious_ips.txt"))
        for ln in lines("ja3_blocklist.txt"):
            parts = [p.strip() for p in ln.split(",", 1)]
            intel.ja3[parts[0].lower()] = parts[1] if len(parts) > 1 else "Blocklisted JA3"
        return intel

    def match_domain(self, name: str) -> str | None:
        name = name.lower().strip(".")
        labels = name.split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self.domains:
                return candidate
        return None

    def summary(self) -> dict:
        return {"domains": len(self.domains), "ips": len(self.ips), "ja3": len(self.ja3)}


def load_thresholds(path: str | None) -> Thresholds:
    th = Thresholds()
    if path:
        with open(path, encoding="utf-8") as fh:
            overrides = json.load(fh)
        for key, value in overrides.items():
            if hasattr(th, key):
                setattr(th, key, type(getattr(th, key))(value))
    return th


def thresholds_dict(th: Thresholds) -> dict:
    return asdict(th)
