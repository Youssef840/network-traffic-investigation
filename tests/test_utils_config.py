import json

import pytest

from nti.config import ThreatIntel, load_thresholds
from nti.detectors import Analyzer
from nti.utils import NetScope, base_domain, defang, fmt_duration, human_bytes, shannon_entropy


@pytest.mark.parametrize("name,expected", [
    ("a.b.example.com", "example.com"),
    ("www.bbc.co.uk", "bbc.co.uk"),
    ("example.com.", "example.com"),
    ("localhost", "localhost"),
])
def test_base_domain(name, expected):
    assert base_domain(name) == expected


def test_entropy_bounds():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_formatting_helpers():
    assert human_bytes(512) == "512 B"
    assert human_bytes(5 * 1024 * 1024) == "5.00 MB"
    assert fmt_duration(3725) == "1h 2m 5s"
    assert defang("http://evil.com") == "hxxp://evil[.]com"


def test_netscope():
    scope = NetScope(["10.0.0.0/8"])
    assert scope.is_internal("10.1.2.3")
    assert not scope.is_internal("8.8.8.8")
    assert scope.is_external("8.8.8.8")


def test_dga_heuristic():
    th = load_thresholds(None)
    assert Analyzer._dga_score("xk7qz9vbt2mwp4hj", th)[0]
    assert not Analyzer._dga_score("google", th)[0]


def test_threat_intel_subdomain_match(tmp_path):
    (tmp_path / "malicious_domains.txt").write_text("# comment\nevil.top\n", encoding="utf-8")
    (tmp_path / "ja3_blocklist.txt").write_text("ABCDEF,Cobalt Strike\n", encoding="utf-8")
    intel = ThreatIntel.load(str(tmp_path))
    assert intel.match_domain("cdn.evil.top.") == "evil.top"
    assert intel.match_domain("notevil.top") is None
    assert intel.ja3 == {"abcdef": "Cobalt Strike"}


def test_threshold_override(tmp_path):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"beacon_min_conns": "12", "unknown_key": 1}), encoding="utf-8")
    th = load_thresholds(str(cfg))
    assert th.beacon_min_conns == 12
    assert not hasattr(th, "unknown_key")
