"""Tests for the UXI multi-step cycle runner.
Slice B1+B2 — UXI Cycle Runner (2026-05-18).
"""
import os
import sys

import pytest

os.environ.setdefault("AGENT_TOKEN", "test-token-for-unit-tests")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app  # noqa: E402


def test_core_cycle_steps_constant_shape():
    """CORE_CYCLE_STEPS is an ordered list of step descriptors."""
    assert isinstance(app.CORE_CYCLE_STEPS, list)
    assert len(app.CORE_CYCLE_STEPS) == 8
    for s in app.CORE_CYCLE_STEPS:
        assert "step_order" in s
        assert "layer" in s
        assert "command" in s
        assert "depends_on" in s
    orders = [s["step_order"] for s in app.CORE_CYCLE_STEPS]
    assert orders == sorted(orders), "steps must be in step_order ascending"


def test_core_cycle_step_orders_match_spec():
    """Core orders 10..80, no gaps in the network-experience sequence."""
    expected = [10, 20, 30, 40, 50, 60, 70, 80]
    actual = [s["step_order"] for s in app.CORE_CYCLE_STEPS]
    assert actual == expected


def test_core_cycle_layers_match_spec():
    """Layers in the order the spec defines."""
    expected = ["rf", "rf", "association", "ip_stack",
                "connectivity", "name_resolution", "name_resolution", "connectivity"]
    actual = [s["layer"] for s in app.CORE_CYCLE_STEPS]
    assert actual == expected


def test_compose_cycle_steps_core_only():
    """No profiles supplied → returns just core."""
    composed = app._compose_cycle_steps([])
    assert len(composed) == 8
    assert [s["step_order"] for s in composed] == [10, 20, 30, 40, 50, 60, 70, 80]


def test_compose_cycle_steps_with_one_profile():
    """One profile with 2 steps → core + 2 app-layer steps at orders 100, 101."""
    profiles = [{
        "id": "microsoft_teams",
        "steps": [
            {"type": "http", "url": "https://teams.microsoft.com"},
            {"type": "ping", "target": "teams.microsoft.com"},
        ],
    }]
    composed = app._compose_cycle_steps(profiles)
    assert len(composed) == 10  # 8 core + 2 app
    assert composed[8]["step_order"] == 100
    assert composed[8]["layer"] == "application"
    assert composed[8]["command"] == "http"
    assert composed[9]["step_order"] == 101
    assert composed[9]["command"] == "ping"


def test_compose_cycle_steps_multiple_profiles_concatenate():
    """Two profiles → first at 100s, second at 200s."""
    profiles = [
        {"id": "a", "steps": [{"type": "http", "url": "https://a.example"}]},
        {"id": "b", "steps": [{"type": "http", "url": "https://b.example"},
                              {"type": "ping", "target": "b.example"}]},
    ]
    composed = app._compose_cycle_steps(profiles)
    assert len(composed) == 11
    assert composed[8]["step_order"] == 100   # a's first
    assert composed[9]["step_order"] == 200   # b's first (jumps to 200, not 101)
    assert composed[10]["step_order"] == 201  # b's second


def test_compose_cycle_steps_app_step_default_depends_on_80():
    """App-layer steps default to depends_on=[80] (need internet)."""
    profiles = [{"id": "x", "steps": [{"type": "http", "url": "https://x.example"}]}]
    composed = app._compose_cycle_steps(profiles)
    assert composed[8]["depends_on"] == [80]


def test_make_skipped_envelope():
    """_make_skipped produces a complete step result envelope."""
    step = {"step_order": 30, "layer": "association",
            "command": "association_test", "depends_on": [20]}
    result = app._make_skipped(step, "skipped: sensor_mode_passive")
    assert result["status"] == "skipped"
    assert result["step_order"] == 30
    assert result["layer"] == "association"
    assert result["command"] == "association_test"
    assert result["error"] == "skipped: sensor_mode_passive"
    assert result["duration_ms"] == 0
    assert "started_at" in result
    assert "completed_at" in result


@pytest.mark.asyncio
async def test_run_step_ap_scan_uses_capability_iface(monkeypatch):
    """ap_scan step calls run_ap_scan with the detected wifi_iface."""
    captured = {}
    def fake_ap_scan(interface="wlan0"):
        captured["interface"] = interface
        return {"success": True, "interface": interface, "aps": [], "timestamp": 1.0}
    monkeypatch.setattr(app, "run_ap_scan", fake_ap_scan)
    monkeypatch.setattr(app, "detect_wifi_iface", lambda: "wlp2s0")

    step = {"step_order": 10, "layer": "rf", "command": "ap_scan", "depends_on": []}
    result = await app._run_step(step, expected_ssid=None)
    assert captured["interface"] == "wlp2s0"
    assert result["status"] == "passed"
    assert result["target"] == "wlp2s0"


@pytest.mark.asyncio
async def test_run_step_dns_primary_uses_first_resolver(monkeypatch):
    """dns_primary uses the first DNS server from /etc/resolv.conf."""
    captured = {}
    def fake_dns(target="google.com", server="", record_type="A"):
        captured["server"] = server
        return {"success": True, "target": target, "server": server,
                "answers": ["1.2.3.4"], "rtt_ms": 12}
    monkeypatch.setattr(app, "run_dns", fake_dns)
    monkeypatch.setattr(app, "get_dns_servers", lambda: ["8.8.8.8", "1.1.1.1"])

    step = {"step_order": 60, "layer": "name_resolution",
            "command": "dns_primary", "depends_on": [50]}
    result = await app._run_step(step, expected_ssid=None)
    assert captured["server"] == "8.8.8.8"
    assert result["status"] == "passed"


@pytest.mark.asyncio
async def test_run_step_dns_secondary_skips_when_no_secondary(monkeypatch):
    """No secondary resolver configured -> step skips itself."""
    monkeypatch.setattr(app, "get_dns_servers", lambda: ["8.8.8.8"])  # only one

    step = {"step_order": 70, "layer": "name_resolution",
            "command": "dns_secondary", "depends_on": [50]}
    result = await app._run_step(step, expected_ssid=None)
    assert result["status"] == "skipped"
    assert "secondary" in result["error"].lower()


@pytest.mark.asyncio
async def test_run_step_internet_ping_two_targets(monkeypatch):
    """internet_ping pings 1.1.1.1 then 8.8.8.8, passes if either passes."""
    called = []
    def fake_ping(target, count=10, size=0, df=False, interval=1.0):
        called.append(target)
        if target == "1.1.1.1":
            return {"success": False, "target": target, "packet_loss_pct": 100.0}
        return {"success": True, "target": target, "packet_loss_pct": 0.0,
                "rtt_avg_ms": 15.2}
    monkeypatch.setattr(app, "run_ping", fake_ping)

    step = {"step_order": 80, "layer": "connectivity",
            "command": "internet_ping", "depends_on": [50]}
    result = await app._run_step(step, expected_ssid=None)
    assert called == ["1.1.1.1", "8.8.8.8"]
    assert result["status"] == "passed"  # 8.8.8.8 passed -> overall pass
    assert "loss_pct_min" in result["result_summary"]


@pytest.mark.asyncio
async def test_run_step_app_http_uses_step_args(monkeypatch):
    """App-profile http step calls run_http_test with the profile-supplied url."""
    captured = {}
    def fake_http(url, follow_redirects=True, timeout=15):
        captured["url"] = url
        return {"success": True, "url": url, "status_code": 200, "total_ms": 220}
    monkeypatch.setattr(app, "run_http_test", fake_http)

    step = {"step_order": 100, "layer": "application", "command": "http",
            "depends_on": [80],
            "_step_args": {"type": "http", "url": "https://teams.microsoft.com"},
            "_profile_id": "microsoft_teams"}
    result = await app._run_step(step, expected_ssid=None)
    assert captured["url"] == "https://teams.microsoft.com"
    assert result["status"] == "passed"


@pytest.mark.asyncio
async def test_run_step_unknown_command_fails(monkeypatch):
    """Unknown command -> step result with status=failed and clear error."""
    step = {"step_order": 999, "layer": "application", "command": "telepathy",
            "depends_on": [80], "_step_args": {}}
    result = await app._run_step(step, expected_ssid=None)
    assert result["status"] == "failed"
    assert "telepathy" in result["error"].lower() or "unknown" in result["error"].lower()


@pytest.mark.asyncio
async def test_run_step_records_duration(monkeypatch):
    """duration_ms is populated."""
    monkeypatch.setattr(app, "run_ap_scan",
                        lambda interface="wlan0": {"success": True, "interface": interface, "aps": []})
    monkeypatch.setattr(app, "detect_wifi_iface", lambda: "wlan0")
    step = {"step_order": 10, "layer": "rf", "command": "ap_scan", "depends_on": []}
    result = await app._run_step(step, expected_ssid=None)
    assert isinstance(result["duration_ms"], (int, float))
    assert result["duration_ms"] >= 0
