import os
import sys

import pytest

os.environ.setdefault("AGENT_TOKEN", "test-token-for-unit-tests")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app  # noqa: E402


def test_validate_wifi_interface_accepts_normal_names():
    assert app.validate_wifi_interface("wlan0") == "wlan0"
    assert app.validate_wifi_interface("wlp2s0") == "wlp2s0"


@pytest.mark.parametrize("bad", ["", "wlan0;reboot", "../wlan0", "wlan 0", "-iface"])
def test_validate_wifi_interface_rejects_shell_shapes(bad):
    with pytest.raises(app.HTTPException):
        app.validate_wifi_interface(bad)


def test_parse_nmcli_wifi_scan_handles_escaped_colons():
    raw = r"My\:SSID:AA\:BB\:CC\:DD\:EE\:FF:6:72:WPA2"
    aps = app.parse_nmcli_wifi_scan(raw)
    assert aps == [{
        "ssid": "My:SSID",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "channel": 6,
        "signal_pct": 72,
        "rssi": -64,
        "security": "WPA2",
    }]


def test_ssid_check_summarises_scan(monkeypatch):
    monkeypatch.setattr(app, "run_ap_scan", lambda interface="wlan0": {
        "success": True,
        "interface": interface,
        "aps": [
            {"ssid": "Corp", "bssid": "aa", "channel": 1, "signal_pct": 30, "rssi": -70},
            {"ssid": "Corp", "bssid": "bb", "channel": 6, "signal_pct": 80, "rssi": -45},
        ],
    })
    result = app.run_ssid_check("Corp", "wlan0")
    assert result["success"] is True
    assert result["visible"] is True
    assert result["bssid_count"] == 2
    assert result["strongest_rssi"] == -45
    assert result["channels"] == [1, 6]


def test_resolve_sensor_mode_defaults_to_passive(monkeypatch):
    monkeypatch.delenv("SENSOR_MODE", raising=False)
    assert app.resolve_sensor_mode() == "passive"


@pytest.mark.parametrize("value,expected", [
    ("passive", "passive"),
    ("active", "active"),
    ("lab", "lab"),
    ("PASSIVE", "passive"),
    ("  active ", "active"),
])
def test_resolve_sensor_mode_accepts_known_values(monkeypatch, value, expected):
    monkeypatch.setenv("SENSOR_MODE", value)
    assert app.resolve_sensor_mode() == expected


@pytest.mark.parametrize("bad", ["banana", "", "active;reboot", "lab\nactive"])
def test_resolve_sensor_mode_coerces_unknown_to_passive(monkeypatch, caplog, bad):
    monkeypatch.setenv("SENSOR_MODE", bad)
    with caplog.at_level("WARNING"):
        assert app.resolve_sensor_mode() == "passive"
    # Empty string is a "default" path — no warning. Anything truthy-but-invalid logs.
    if bad.strip():
        assert any("SENSOR_MODE" in r.getMessage() for r in caplog.records)
