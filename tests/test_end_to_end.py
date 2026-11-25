"""Runs the whole pipeline on the synthetic incident capture and checks that every
planted scenario is detected and every output artifact is produced."""

import csv
import json

import pytest


def _titles(results):
    return " || ".join(f["title"] for f in results["findings"]).lower()


def test_all_artifacts_written(analysis):
    out, _ = analysis
    for suffix in ("report.pdf", "report.html", "stix.json", "results.json", "iocs.csv", "findings.csv"):
        path = out / f"TEST-001_{suffix}"
        assert path.exists() and path.stat().st_size > 0, suffix
    assert (out / "TEST-001_report.pdf").read_bytes().startswith(b"%PDF")


@pytest.mark.parametrize("needle", [
    "blocklisted domain",       # threat intel (DNS + TLS)
    "dga-like",                 # DGA
    "dns tunneling",            # DNS tunneling
    "beaconing",                # C2 beacon
    "port scan",                # recon
    "large outbound transfer",  # exfiltration
    "metasploit",               # backdoor port
    "icmp",                     # ICMP tunnel
    "mac addresses",            # ARP spoofing
    "cleartext",                # credentials
    "without sni",              # TLS anomaly
])
def test_scenario_detected(analysis, needle):
    _, results = analysis
    assert needle in _titles(results)


def test_risk_and_tls_volume(analysis):
    _, res = analysis
    assert res["risk"]["level"] == "Critical"
    assert res["tls"]["sessions"] > 0
    top = res["tls"]["servers"][0]
    assert top["total"] == top["bytes_in"] + top["bytes_out"] > 0


def test_ioc_csv_matches_json(analysis):
    out, res = analysis
    with open(out / "TEST-001_iocs.csv", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert {r["value"] for r in rows} == {i["value"] for i in res["iocs"]}


def test_stix_bundle_valid(analysis):
    out, _ = analysis
    bundle = json.loads((out / "TEST-001_stix.json").read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle"
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert indicators and all(o["pattern"].startswith("[") for o in indicators)
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert set(report["object_refs"]) == {o["id"] for o in indicators}


def test_html_is_self_contained(analysis):
    out, _ = analysis
    html = (out / "TEST-001_report.html").read_text(encoding="utf-8")
    assert "<script src=" not in html and "<link " not in html
    assert "update-check-svc[.]top" in html


def test_cli_rejects_missing_file(tmp_path):
    from nti.cli import main

    assert main([str(tmp_path / "nope.pcap"), "-q"]) == 2
