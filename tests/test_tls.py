from nti.tls import is_grease, parse_client_hello, tls_record_info

from .conftest import make_client_hello


def test_grease_values():
    assert is_grease(0x0A0A) and is_grease(0xFAFA)
    assert not is_grease(0x1301)


def test_record_info_rejects_non_tls():
    assert tls_record_info(b"GET / HTTP/1.1\r\n") is None
    assert tls_record_info(b"\x16\x03") is None


def test_parse_client_hello_extracts_sni_and_ja3():
    res = parse_client_hello(make_client_hello("Evil.Example.COM"))
    assert res["sni"] == "evil.example.com"
    assert res["version_name"].startswith("TLS")
    assert res["cipher_count"] == 4
    # GREASE (0x0a0a = 2570) must be stripped from the JA3 string
    assert "2570" not in res["ja3"]
    assert res["ja3"] == "771,4865-4866-49199,0-10-11,29-23,0"
    assert len(res["ja3_hash"]) == 32


def test_ja3_is_stable_across_grease():
    a = parse_client_hello(make_client_hello(grease=True))["ja3_hash"]
    b = parse_client_hello(make_client_hello(grease=False))["ja3_hash"]
    assert a == b


def test_incomplete_and_invalid():
    hello = make_client_hello()
    assert parse_client_hello(hello[:20]) == {"incomplete": True}
    assert parse_client_hello(b"\x17\x03\x03\x00\x05hello") is None
