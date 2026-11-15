#!/usr/bin/env python3
"""Network Traffic Investigation - command line entry point.

Usage:
    python analyze.py capture.pcap [more.pcapng ...] [options]

Produces in the output directory:
    <case>_report.pdf     executive + tactical PDF report
    <case>_results.json   full machine-readable results
    <case>_iocs.csv       IOC list (SIEM / firewall ready)
    <case>_findings.csv   all findings
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone

from nti import __version__
from nti.collector import TrafficCollector
from nti.config import ThreatIntel, load_thresholds, thresholds_dict
from nti.detectors import Analyzer
from nti.utils import DEFAULT_INTERNAL_CIDRS, NetScope, file_hashes, fmt_ts, human_bytes

BANNER = r"""
  _   _ _____ ___   Network Traffic Investigation
 | \ | |_   _|_ _|  PCAP forensics: DNS | TLS | Anomalies | IOCs
 |  \| | | |  | |   v{ver}
 | |\  | | |  | |
 |_| \_| |_| |___|
"""

SEV_TAG = {"Critical": "[CRIT]", "High": "[HIGH]", "Medium": "[MED ]", "Low": "[LOW ]", "Info": "[INFO]"}


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Analyze PCAP files and generate an investigation report.")
    p.add_argument("pcaps", nargs="+", help="PCAP / PCAPNG file(s) to analyze")
    p.add_argument("-o", "--output", default="reports", help="output directory (default: reports)")
    p.add_argument("--case-id", default=None, help="case identifier (default: NTI-<timestamp>)")
    p.add_argument("--analyst", default="SOC Analyst", help="analyst name shown in the report")
    p.add_argument("--tlp", default="AMBER", choices=["CLEAR", "GREEN", "AMBER", "RED"], help="TLP marking")
    p.add_argument("--internal", nargs="*", default=None, metavar="CIDR",
                   help="internal network ranges (default: RFC1918 + loopback/link-local)")
    p.add_argument("--intel-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "iocs"),
                   help="directory with malicious_domains.txt / malicious_ips.txt / ja3_blocklist.txt")
    p.add_argument("--config", default=None, help="JSON file overriding detection thresholds")
    p.add_argument("--exfil-mb", type=float, default=None, help="outbound MB per host pair that triggers exfil alert")
    p.add_argument("--max-packets", type=int, default=None, help="stop after N packets per file")
    p.add_argument("--no-pdf", action="store_true", help="skip PDF generation (JSON/CSV only)")
    p.add_argument("-q", "--quiet", action="store_true", help="minimal console output")
    return p.parse_args(argv)


def write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def main(argv=None) -> int:
    args = parse_args(argv)
    if not args.quiet:
        print(BANNER.format(ver=__version__))

    for path in args.pcaps:
        if not os.path.isfile(path):
            print(f"[!] File not found: {path}", file=sys.stderr)
            return 2

    case_id = args.case_id or "NTI-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    th = load_thresholds(args.config)
    if args.exfil_mb is not None:
        th.exfil_bytes = int(args.exfil_mb * 1024 * 1024)
    intel = ThreatIntel.load(args.intel_dir)
    scope = NetScope(args.internal or DEFAULT_INTERNAL_CIDRS)

    t0 = time.time()
    col = TrafficCollector(verbose=not args.quiet)
    files_meta = []
    for path in args.pcaps:
        if not args.quiet:
            print(f"[*] Hashing  {path}")
        hashes = file_hashes(path)
        files_meta.append({"name": os.path.basename(path), "path": os.path.abspath(path),
                           "size": os.path.getsize(path), **hashes})
        if not args.quiet:
            print(f"[*] Parsing  {path}  ({human_bytes(os.path.getsize(path))})")
        col.load(path, args.max_packets)

    if col.total_packets == 0:
        print("[!] No packets could be read.", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"[*] Parsed {col.total_packets:,} packets / {len(col.flows):,} flows in {time.time() - t0:.1f}s")
        print("[*] Running detections ...")

    analysis = Analyzer(col, th, intel, scope).run()
    results = {
        "meta": {
            "tool": f"NTI v{__version__}",
            "case_id": case_id,
            "analyst": args.analyst,
            "tlp": args.tlp,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "files": files_meta,
            "internal_cidrs": scope.cidrs,
            "intel": intel.summary(),
            "thresholds": thresholds_dict(th),
            "analysis_seconds": round(time.time() - t0, 2),
        },
        "stats": {
            "packets": col.total_packets,
            "bytes": col.total_bytes,
            "start": col.first_ts,
            "end": col.last_ts,
            "duration": (col.last_ts or 0) - (col.first_ts or 0),
            "errors": col.errors,
        },
        **analysis,
    }

    os.makedirs(args.output, exist_ok=True)
    base = os.path.join(args.output, case_id)
    with open(base + "_results.json", "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, default=str)
    write_csv(base + "_iocs.csv", ["type", "value", "severity", "hits", "first_seen", "categories", "context"],
              [[i["type"], i["value"], i["severity"], i["hits"], fmt_ts(i["first_seen"]),
                "; ".join(i["categories"]), i["context"]] for i in results["iocs"]])
    write_csv(base + "_findings.csv",
              ["id", "severity", "category", "title", "src", "dst", "mitre", "count", "first_seen", "evidence"],
              [[f"F-{n:03d}", f["severity"], f["category"], f["title"], f["src"], f["dst"], f["mitre"],
                f["count"], fmt_ts(f["first_seen"]), " | ".join(map(str, f["evidence"]))]
               for n, f in enumerate(results["findings"], 1)])
    pdf_path = None
    if not args.no_pdf:
        from nti.report_pdf import build_pdf
        if not args.quiet:
            print("[*] Building PDF report ...")
        pdf_path = build_pdf(results, base + "_report.pdf")

    # ------------------------------------------------------- console summary
    risk = results["risk"]
    print("\n" + "=" * 72)
    print(f" CASE {case_id}   RISK: {risk['level'].upper()} ({risk['score']}/100)")
    print("=" * 72)
    print(f" Packets: {col.total_packets:,}  Volume: {human_bytes(col.total_bytes)}  "
          f"DNS queries: {results['dns']['total_queries']:,}  TLS sessions: {results['tls']['sessions']:,}")
    print(f" Findings: {len(results['findings'])}  " +
          "  ".join(f"{k}={v}" for k, v in risk["by_severity"].items() if v) +
          f"   IOCs: {len(results['iocs'])}")
    print("-" * 72)
    for f in results["findings"][:25]:
        print(f" {SEV_TAG[f['severity']]} {f['title'][:64]}")
    if len(results["findings"]) > 25:
        print(f" ... and {len(results['findings']) - 25} more (see report)")
    print("-" * 72)
    if pdf_path:
        print(f" PDF report : {os.path.abspath(pdf_path)}")
    print(f" JSON       : {os.path.abspath(base + '_results.json')}")
    print(f" IOC CSV    : {os.path.abspath(base + '_iocs.csv')}")
    print(f" Findings   : {os.path.abspath(base + '_findings.csv')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
