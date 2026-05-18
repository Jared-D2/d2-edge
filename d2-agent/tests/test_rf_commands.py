import json
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


IW_SCAN_TWO_APS = """BSS d0:db:b7:9a:5f:03(on wlan0)
\tTSF: 0 usec (0d, 00:00:00)
\tfreq: 2452.0
\tsignal: -52.00 dBm
\tSSID: NetComm 2918
\tDS Parameter set: channel 9
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\tBSS Load:
\t\t * station count: 0
\t\t * channel utilisation: 12/255
\tBSS Membership Selectors:
\t\t * SAE Hash-to-Element only
\tHT capabilities:
\t\tCapabilities: 0x9bc
BSS 70:4c:a5:dc:76:60(on wlan0) -- associated
\tTSF: 0 usec
\tfreq: 5825.0
\tsignal: -60.00 dBm
\tSSID: D2-CORP
\tDS Parameter set: channel 165
\tBSS Load:
\t\t * station count: 0
"""


def test_parse_iw_wifi_scan_ignores_bss_subsections():
    aps = app.parse_iw_wifi_scan(IW_SCAN_TWO_APS)
    assert [a["bssid"] for a in aps] == [
        "d0:db:b7:9a:5f:03",
        "70:4c:a5:dc:76:60",
    ]
    assert aps[0]["ssid"] == "NetComm 2918"
    assert aps[0]["channel"] == 9
    assert aps[0]["rssi"] == -52.0
    assert aps[1]["ssid"] == "D2-CORP"
    assert aps[1]["channel"] == 165
    assert aps[1]["rssi"] == -60.0


def test_parse_iw_wifi_scan_handles_uppercase_mac():
    raw = "BSS AA:BB:CC:DD:EE:FF(on wlan0)\n\tSSID: foo\n\tBSS Load:\n\t\t * station count: 1\n"
    aps = app.parse_iw_wifi_scan(raw)
    assert len(aps) == 1
    assert aps[0]["bssid"] == "AA:BB:CC:DD:EE:FF"


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


def test_system_info_reports_sensor_mode_and_capabilities(monkeypatch):
    monkeypatch.setattr(app, "SENSOR_MODE", "passive")
    monkeypatch.setattr(app, "detect_wifi_iface", lambda: "wlan0")
    monkeypatch.setattr(app.shutil, "which",
                        lambda name: "/usr/bin/nmcli" if name == "nmcli" else None)
    app._last_rf_error = None
    info = app.system_info()
    assert info["sensor_mode"] == "passive"
    caps = info["capabilities"]
    assert caps["rf_scan"] is True
    assert caps["rf_tool"] == "nmcli"
    assert caps["wifi_iface"] == "wlan0"
    assert caps["association_test"] is False  # passive
    assert caps["last_rf_error"] is None


def test_system_info_reports_no_rf_when_no_wireless_iface(monkeypatch):
    monkeypatch.setattr(app, "SENSOR_MODE", "passive")
    monkeypatch.setattr(app, "detect_wifi_iface", lambda: None)
    monkeypatch.setattr(app.shutil, "which",
                        lambda name: "/usr/bin/nmcli" if name == "nmcli" else None)
    info = app.system_info()
    caps = info["capabilities"]
    assert caps["rf_scan"] is False
    assert caps["rf_tool"] == "nmcli"  # tool is installed but no iface
    assert caps["wifi_iface"] is None
    assert caps["association_test"] is False


def test_system_info_reports_association_test_when_active(monkeypatch):
    monkeypatch.setattr(app, "SENSOR_MODE", "active")
    monkeypatch.setattr(app, "detect_wifi_iface", lambda: "wlan0")
    monkeypatch.setattr(app.shutil, "which",
                        lambda name: "/usr/bin/nmcli" if name == "nmcli" else None)
    info = app.system_info()
    assert info["capabilities"]["association_test"] is True


def test_system_info_prefers_nmcli_over_iw(monkeypatch):
    monkeypatch.setattr(app, "SENSOR_MODE", "passive")
    monkeypatch.setattr(app, "detect_wifi_iface", lambda: "wlan0")
    def fake_which(name):
        return "/usr/bin/" + name if name in ("nmcli", "iw") else None
    monkeypatch.setattr(app.shutil, "which", fake_which)
    info = app.system_info()
    assert info["capabilities"]["rf_tool"] == "nmcli"


def test_system_info_uses_iw_when_only_iw_available(monkeypatch):
    monkeypatch.setattr(app, "SENSOR_MODE", "passive")
    monkeypatch.setattr(app, "detect_wifi_iface", lambda: "wlan0")
    monkeypatch.setattr(app.shutil, "which",
                        lambda name: "/usr/sbin/iw" if name == "iw" else None)
    info = app.system_info()
    assert info["capabilities"]["rf_tool"] == "iw"
    assert info["capabilities"]["rf_scan"] is True


def test_system_info_reports_no_rf_tool_when_neither_installed(monkeypatch):
    monkeypatch.setattr(app, "SENSOR_MODE", "passive")
    monkeypatch.setattr(app, "detect_wifi_iface", lambda: "wlan0")
    monkeypatch.setattr(app.shutil, "which", lambda name: None)
    info = app.system_info()
    caps = info["capabilities"]
    assert caps["rf_tool"] is None
    assert caps["rf_scan"] is False  # no tool, even though iface exists


class _FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, msg):
        self.sent.append(msg)


@pytest.mark.asyncio
async def test_handle_command_refuses_association_test_when_passive(monkeypatch):
    monkeypatch.setattr(app, "SENSOR_MODE", "passive")
    monkeypatch.setattr(app, "ALLOWED_COMMANDS", None)
    monkeypatch.setattr(app, "run_association_test",
                        lambda *a, **kw: pytest.fail("must not be called"))
    ws = _FakeWS()
    payload = json.dumps({
        "command": "association_test",
        "job_id": "job-1",
        "params": {"ssid": "Corp", "interface": "wlan0"},
    })
    await app.handle_command(ws, payload)
    assert len(ws.sent) == 1
    sent = json.loads(ws.sent[0])
    assert sent["command"] == "association_test"
    assert "refused" in sent["result"]["error"].lower()
    assert "passive" in sent["result"]["error"]


@pytest.mark.asyncio
async def test_handle_command_allows_association_test_when_active(monkeypatch):
    monkeypatch.setattr(app, "SENSOR_MODE", "active")
    monkeypatch.setattr(app, "ALLOWED_COMMANDS", None)
    called = {}
    def fake_run(ssid, interface="wlan0", timeout=20, password=""):
        called["ssid"] = ssid
        return {"success": True, "interface": interface, "ssid": ssid}
    monkeypatch.setattr(app, "run_association_test", fake_run)
    ws = _FakeWS()
    payload = json.dumps({
        "command": "association_test",
        "job_id": "job-2",
        "params": {"ssid": "Corp", "interface": "wlan0"},
    })
    await app.handle_command(ws, payload)
    assert called["ssid"] == "Corp"
    sent = json.loads(ws.sent[0])
    assert sent["result"]["success"] is True


@pytest.mark.asyncio
async def test_handle_command_refuses_association_test_when_lab_allows(monkeypatch):
    """lab mode is the most permissive — also allows association_test."""
    monkeypatch.setattr(app, "SENSOR_MODE", "lab")
    monkeypatch.setattr(app, "ALLOWED_COMMANDS", None)
    called = {}
    def fake_run(ssid, interface="wlan0", timeout=20, password=""):
        called["ssid"] = ssid
        return {"success": True}
    monkeypatch.setattr(app, "run_association_test", fake_run)
    ws = _FakeWS()
    payload = json.dumps({
        "command": "association_test",
        "job_id": "job-3",
        "params": {"ssid": "Corp", "interface": "wlan0"},
    })
    await app.handle_command(ws, payload)
    assert called.get("ssid") == "Corp"
