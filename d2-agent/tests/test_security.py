"""Security-focused unit tests for d2-agent input validators and SSRF guards.

These cover the parts of app.py where a bug would have real blast radius:
argv-injection into ping/nmap/dig, SSRF against cloud metadata, and the
traceroute parser (a bad parse could feed malformed data to the controller).

They deliberately avoid network I/O. getaddrinfo is monkeypatched so DNS
checks are deterministic across CI environments.
"""
import os
import sys

import pytest

# app.py refuses to import without AGENT_TOKEN; set a dummy before import.
os.environ.setdefault("AGENT_TOKEN", "test-token-for-unit-tests")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import HTTPException  # noqa: E402

import app  # noqa: E402


# ─── validate_target ────────────────────────────────────────────────────────
class TestValidateTarget:
    @pytest.mark.parametrize("good", [
        "8.8.8.8",
        "google.com",
        "www.example.co.uk",
        "host-with-dash.example.com",
        "a.b.c.d.e.f.g.h",
        "2001-db8--1",  # letters/digits/dashes only — IPv6 literals
        "xn--nxasmq6b",
    ])
    def test_accepts_normal_hostnames_and_ips(self, good):
        assert app.validate_target(good) == good

    @pytest.mark.parametrize("bad", [
        "-f",            # ping/traceroute flag
        "--iflist",      # nmap flag
        "-rfw1",         # ping -r/-f/-w style
        "-",             # nmap "scan all" marker
        "-oN",           # nmap output
        "",              # empty
        ".leading.dot",
        "trailing.dot.",
        "space in name",
        "semi;colon",
        "pipe|here",
        "back`tick`",
        "quote\"here",
        "$(subshell)",
        "a" * 254,       # over 253 chars
    ])
    def test_rejects_argv_injection_and_malformed(self, bad):
        with pytest.raises(HTTPException) as exc:
            app.validate_target(bad)
        assert exc.value.status_code == 400

    def test_rejects_non_string(self):
        for bad in [None, 123, ["a"], {"x": 1}]:
            with pytest.raises(HTTPException):
                app.validate_target(bad)


# ─── validate_port_spec ─────────────────────────────────────────────────────
class TestValidatePortSpec:
    @pytest.mark.parametrize("good", [
        "22",
        "80,443",
        "1-1024",
        "22,80,443,8080-8090",
    ])
    def test_accepts_valid_port_specs(self, good):
        assert app.validate_port_spec(good) == good

    @pytest.mark.parametrize("bad", [
        "-",                       # all ports — nmap sentinel, denied
        "-p1-65535",               # option-style
        "abc",
        "22,",
        ",22",
        "22-",
        "22;80",
        "$(rm)",
        "",
    ])
    def test_rejects_malformed_or_shell(self, bad):
        with pytest.raises(HTTPException):
            app.validate_port_spec(bad)


# ─── validate_dns_record_type ───────────────────────────────────────────────
class TestValidateDnsRecordType:
    @pytest.mark.parametrize("good,expected", [
        ("A", "A"), ("a", "A"),
        ("AAAA", "AAAA"), ("aaaa", "AAAA"),
        ("CNAME", "CNAME"), ("MX", "MX"),
        ("NS", "NS"), ("PTR", "PTR"),
        ("SOA", "SOA"), ("SRV", "SRV"),
        ("TXT", "TXT"), ("CAA", "CAA"),
    ])
    def test_accepts_rfc_types_case_insensitive(self, good, expected):
        assert app.validate_dns_record_type(good) == expected

    @pytest.mark.parametrize("bad", [
        "ANY",           # dig -t ANY can hammer resolvers; not whitelisted
        "AXFR",          # zone transfer
        "DNSKEY",
        "",
        "A ;",
        None,
    ])
    def test_rejects_non_whitelisted(self, bad):
        with pytest.raises(HTTPException):
            app.validate_dns_record_type(bad)


# ─── _ip_is_blocked / _looks_like_ip_literal ────────────────────────────────
class TestIpBlocking:
    @pytest.mark.parametrize("blocked", [
        "127.0.0.1",         # loopback
        "127.1.2.3",         # full /8 loopback
        "169.254.169.254",   # AWS/Azure/GCP metadata
        "169.254.1.1",       # link-local
        "224.0.0.1",         # multicast
        "0.0.0.0",           # unspecified
        "::1",               # IPv6 loopback
        "fe80::1",           # IPv6 link-local
        "fd00:ec2::254",     # IPv6 metadata alias
    ])
    def test_blocks_unsafe_ips(self, blocked):
        assert app._ip_is_blocked(blocked) is True

    @pytest.mark.parametrize("allowed", [
        "8.8.8.8",
        "1.1.1.1",
        "10.0.0.1",          # RFC1918 — intentionally allowed (customer LAN)
        "192.168.1.1",
        "172.16.0.1",
        "100.64.0.1",        # CGNAT / Tailscale — allowed
        "203.0.113.5",       # TEST-NET-3 public
    ])
    def test_allows_public_and_customer_lan(self, allowed):
        assert app._ip_is_blocked(allowed) is False

    def test_non_ip_strings_do_not_raise(self):
        # Must return False (not an IP literal → validator will reject
        # later via TARGET_RE). _ip_is_blocked should not crash.
        assert app._ip_is_blocked("not-an-ip") is False

    def test_looks_like_ip_literal(self):
        assert app._looks_like_ip_literal("8.8.8.8") is True
        assert app._looks_like_ip_literal("::1") is True
        assert app._looks_like_ip_literal("example.com") is False
        assert app._looks_like_ip_literal("") is False


# ─── _resolve_and_check ─────────────────────────────────────────────────────
class TestResolveAndCheck:
    @pytest.fixture
    def patch_dns(self, monkeypatch):
        """Install a fake getaddrinfo that returns whatever the test requests."""
        def make(ip_list):
            def fake_getaddrinfo(host, _port, **_kwargs):
                return [(0, 0, 0, "", (ip, 0)) for ip in ip_list]
            monkeypatch.setattr(app.socket, "getaddrinfo", fake_getaddrinfo)
        return make

    def test_blocks_metadata_hostname(self):
        # Literal match — no DNS required.
        blocked, ips = app._resolve_and_check("metadata.google.internal")
        assert blocked is True

    def test_blocks_instance_metadata_hostname(self):
        blocked, _ = app._resolve_and_check("metadata")
        assert blocked is True

    def test_blocks_dns_rebinding_when_any_ip_is_metadata(self, patch_dns):
        # Classic rebinding: resolver returns a public IP AND 169.254.169.254
        # (or just metadata). Every returned IP must be safe.
        patch_dns(["8.8.8.8", "169.254.169.254"])
        blocked, ips = app._resolve_and_check("attacker.example.com")
        assert blocked is True
        assert "169.254.169.254" in ips

    def test_allows_public_only_resolution(self, patch_dns):
        patch_dns(["8.8.8.8", "1.1.1.1"])
        blocked, ips = app._resolve_and_check("dns.example.com")
        assert blocked is False
        assert set(ips) == {"8.8.8.8", "1.1.1.1"}

    def test_allows_rfc1918_customer_lan(self, patch_dns):
        patch_dns(["10.1.2.3"])
        blocked, _ = app._resolve_and_check("printer.local.lan")
        assert blocked is False

    def test_blocks_unresolvable_host(self, monkeypatch):
        def boom(*_a, **_kw):
            raise app.socket.gaierror("not found")
        monkeypatch.setattr(app.socket, "getaddrinfo", boom)
        blocked, ips = app._resolve_and_check("does-not-exist.invalid")
        assert blocked is True
        assert ips == []

    def test_blocks_ip_literal_loopback(self):
        blocked, ips = app._resolve_and_check("127.0.0.1")
        assert blocked is True

    def test_allows_ip_literal_public(self):
        blocked, ips = app._resolve_and_check("8.8.8.8")
        assert blocked is False

    def test_empty_host(self):
        blocked, ips = app._resolve_and_check("")
        assert blocked is True
        assert ips == []


# ─── parse_traceroute ───────────────────────────────────────────────────────
class TestParseTraceroute:
    def test_parses_standard_traceroute_output(self):
        raw = (
            "traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets\n"
            " 1  192.168.1.1  1.234 ms  1.456 ms  1.789 ms\n"
            " 2  10.0.0.1  5.1 ms  5.2 ms  5.3 ms\n"
            " 3  * * *\n"
            " 4  8.8.8.8  12.5 ms  12.6 ms  12.7 ms\n"
        )
        hops = app.parse_traceroute(raw)
        assert len(hops) == 4
        assert hops[0]["hop"] == 1
        assert hops[0]["ip"] == "192.168.1.1"
        assert hops[0]["rtts"] == [1.234, 1.456, 1.789]
        assert hops[0]["loss_pct"] == 0.0
        assert hops[2]["rtts"] == [None, None, None]
        assert hops[2]["loss_pct"] == 100.0
        assert hops[3]["ip"] == "8.8.8.8"

    def test_empty_input_returns_empty_list(self):
        assert app.parse_traceroute("") == []

    def test_header_only_returns_empty(self):
        raw = "traceroute to 8.8.8.8 (8.8.8.8), 30 hops max\n"
        assert app.parse_traceroute(raw) == []

    def test_non_numeric_first_field_is_skipped(self):
        raw = (
            "header\n"
            "xx bogus line\n"
            " 1  1.1.1.1  1.0 ms\n"
        )
        hops = app.parse_traceroute(raw)
        assert len(hops) == 1
        assert hops[0]["hop"] == 1
