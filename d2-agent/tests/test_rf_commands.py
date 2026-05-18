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


def test_detect_wifi_iface_returns_none_when_no_wireless(monkeypatch, tmp_path):
    (tmp_path / "eth0").mkdir()
    monkeypatch.setattr(app, "SYS_CLASS_NET", str(tmp_path))
    assert app.detect_wifi_iface() is None


def test_detect_wifi_iface_returns_wlan0_when_present(monkeypatch, tmp_path):
    (tmp_path / "eth0").mkdir()
    wlan0 = tmp_path / "wlan0"
    wlan0.mkdir()
    (wlan0 / "wireless").mkdir()
    monkeypatch.setattr(app, "SYS_CLASS_NET", str(tmp_path))
    assert app.detect_wifi_iface() == "wlan0"


def test_detect_wifi_iface_picks_alphabetically_first(monkeypatch, tmp_path):
    for name in ("wlp2s0", "wlan0"):
        d = tmp_path / name
        d.mkdir()
        (d / "wireless").mkdir()
    monkeypatch.setattr(app, "SYS_CLASS_NET", str(tmp_path))
    assert app.detect_wifi_iface() == "wlan0"


def test_detect_wifi_iface_returns_none_when_sys_class_net_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(app, "SYS_CLASS_NET", str(tmp_path / "does-not-exist"))
    assert app.detect_wifi_iface() is None


def test_last_rf_error_cleared_on_successful_scan(monkeypatch):
    app._last_rf_error = "stale failure"
    monkeypatch.setattr(app.shutil, "which",
                        lambda name: "/usr/bin/nmcli" if name == "nmcli" else None)
    monkeypatch.setattr(app, "run_cmd", lambda cmd, timeout=60: (True, ""))
    result = app.run_ap_scan("wlan0")
    assert result["success"] is True
    assert app._last_rf_error is None


def test_last_rf_error_set_on_failed_scan(monkeypatch):
    app._last_rf_error = None
    monkeypatch.setattr(app.shutil, "which",
                        lambda name: "/usr/bin/nmcli" if name == "nmcli" else None)
    monkeypatch.setattr(app, "run_cmd",
                        lambda cmd, timeout=60: (False, "Device 'wlan0' not found"))
    result = app.run_ap_scan("wlan0")
    assert result["success"] is False
    assert app._last_rf_error is not None
    assert "wlan0" in app._last_rf_error
    assert len(app._last_rf_error) <= 200


def test_last_rf_error_set_when_no_tools(monkeypatch):
    app._last_rf_error = None
    monkeypatch.setattr(app.shutil, "which", lambda name: None)
    result = app.run_ap_scan("wlan0")
    assert result["success"] is False
    assert app._last_rf_error is not None


def test_last_rf_error_trimmed_to_200_chars(monkeypatch):
    app._last_rf_error = None
    long_err = "x" * 500
    monkeypatch.setattr(app.shutil, "which",
                        lambda name: "/usr/bin/nmcli" if name == "nmcli" else None)
    monkeypatch.setattr(app, "run_cmd", lambda cmd, timeout=60: (False, long_err))
    app.run_ap_scan("wlan0")
    assert app._last_rf_error is not None
    assert len(app._last_rf_error) <= 200


def test_last_rf_error_cleared_on_successful_ssid_check(monkeypatch):
    app._last_rf_error = "stale"
    # Stub run_ap_scan to return a successful scan that matches the SSID.
    monkeypatch.setattr(app, "run_ap_scan", lambda interface="wlan0": {
        "success": True, "interface": interface,
        "aps": [{"ssid": "Corp", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 1, "rssi": -50}],
    })
    result = app.run_ssid_check("Corp", "wlan0")
    assert result["visible"] is True
    assert app._last_rf_error is None


def test_last_rf_error_set_on_ssid_check_failure(monkeypatch):
    app._last_rf_error = None
    monkeypatch.setattr(app, "run_ap_scan", lambda interface="wlan0": {
        "success": False, "interface": interface, "aps": [],
        "error": "scan tool crashed",
    })
    result = app.run_ssid_check("Corp", "wlan0")
    assert result["visible"] is False
    assert app._last_rf_error is not None
    assert "scan" in app._last_rf_error.lower() or "ssid" in app._last_rf_error.lower()
