"""Tests for host-exhaustion (PID/thread cap) handling.

The 2026-05-01 nib001-sy-pi01 incident exposed that probe modules were
treating fork-failure (BlockingIOError / RuntimeError "can't start new
thread") identically to a real network failure, emitting structurally
empty success=0 results that the controller stored as legitimate
incidents. These tests pin down the contract:

  - run_cmd raises SpawnFailureError on EAGAIN/ENOMEM/can't-start-thread
  - run_cmd still returns (False, errstr) for real subprocess errors
  - run_traceroute always carries the `target` field, even on mtr failure
  - run_dns falls back to in-process getaddrinfo when dig can't fork
  - _spawn_failure_result tags results with spawn_failure=True
"""
import errno
import os
import subprocess
import sys

import pytest

os.environ.setdefault("AGENT_TOKEN", "test-token-for-unit-tests")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app  # noqa: E402


class TestIsSpawnExhaustion:
    def test_blockingioerror(self):
        assert app._is_spawn_exhaustion(BlockingIOError())

    def test_oserror_eagain(self):
        e = OSError(errno.EAGAIN, "Resource temporarily unavailable")
        assert app._is_spawn_exhaustion(e)

    def test_oserror_enomem(self):
        e = OSError(errno.ENOMEM, "Cannot allocate memory")
        assert app._is_spawn_exhaustion(e)

    def test_runtimeerror_thread(self):
        assert app._is_spawn_exhaustion(RuntimeError("can't start new thread"))

    def test_runtimeerror_other(self):
        assert not app._is_spawn_exhaustion(RuntimeError("nope"))

    def test_oserror_unrelated(self):
        # ENOENT (file not found) is a real subprocess error, not exhaustion.
        e = OSError(errno.ENOENT, "No such file")
        assert not app._is_spawn_exhaustion(e)

    def test_value_error(self):
        assert not app._is_spawn_exhaustion(ValueError("bad"))


class TestRunCmdSpawnFailure:
    def test_eagain_raises_spawn_failure(self, monkeypatch):
        def fake_check_output(*a, **kw):
            raise BlockingIOError(errno.EAGAIN, "Resource temporarily unavailable")
        monkeypatch.setattr(subprocess, "check_output", fake_check_output)
        with pytest.raises(app.SpawnFailureError):
            app.run_cmd(["ping", "-c", "1", "8.8.8.8"])

    def test_thread_runtimeerror_raises_spawn_failure(self, monkeypatch):
        def fake_check_output(*a, **kw):
            raise RuntimeError("can't start new thread")
        monkeypatch.setattr(subprocess, "check_output", fake_check_output)
        with pytest.raises(app.SpawnFailureError):
            app.run_cmd(["ping", "-c", "1", "8.8.8.8"])

    def test_real_subprocess_failure_still_returns_false(self, monkeypatch):
        # Non-exhaustion exceptions stay as (False, errstr) for backward compat.
        def fake_check_output(*a, **kw):
            raise FileNotFoundError(errno.ENOENT, "No such file: ping")
        monkeypatch.setattr(subprocess, "check_output", fake_check_output)
        ok, raw = app.run_cmd(["ping", "-c", "1", "8.8.8.8"])
        assert ok is False
        assert "ping" in raw or "No such file" in raw

    def test_timeout_still_returns_false(self, monkeypatch):
        def fake_check_output(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="ping", timeout=1)
        monkeypatch.setattr(subprocess, "check_output", fake_check_output)
        ok, raw = app.run_cmd(["ping"])
        assert ok is False
        assert raw == "Command timed out"

    def test_called_process_error_still_returns_false(self, monkeypatch):
        def fake_check_output(*a, **kw):
            raise subprocess.CalledProcessError(returncode=1, cmd="ping",
                                                output=b"unreachable")
        monkeypatch.setattr(subprocess, "check_output", fake_check_output)
        ok, raw = app.run_cmd(["ping"])
        assert ok is False
        assert "unreachable" in raw


class TestRunTracerouteAlwaysHasTarget:
    """The controller defaults missing `target` to "unknown" when storing,
    which makes a fleet-wide spawn outage indistinguishable from real probes.
    Both branches of run_traceroute must include target."""

    def test_mtr_success_includes_target(self, monkeypatch):
        mtr_json = '{"report":{"hubs":[{"count":1,"host":"10.0.0.1","Loss%":0.0,"Avg":1.5}]}}'
        monkeypatch.setattr(app, "run_cmd", lambda *a, **kw: (True, mtr_json))
        result = app.run_traceroute("8.8.8.8", use_mtr=True)
        assert result["target"] == "8.8.8.8"
        assert result["success"] is True

    def test_mtr_failure_includes_target_and_empty_hops(self, monkeypatch):
        # mtr exits non-zero / unparseable — used to return {success=False}
        # WITHOUT target, which the controller stored as target="unknown".
        monkeypatch.setattr(app, "run_cmd", lambda *a, **kw: (False, "EAGAIN"))
        result = app.run_traceroute("8.8.8.8", use_mtr=True)
        assert result["target"] == "8.8.8.8"
        assert result["success"] is False
        assert result["hops"] == []

    def test_traceroute_branch_always_has_target(self, monkeypatch):
        monkeypatch.setattr(app, "run_cmd", lambda *a, **kw: (False, "timeout"))
        result = app.run_traceroute("8.8.8.8", use_mtr=False)
        assert result["target"] == "8.8.8.8"
        assert result["hops"] == []
        assert result["success"] is False


class TestRunDnsFallbackUnderExhaustion:
    """run_dns must keep working when dig can't fork — fall back to
    in-process getaddrinfo. DNS was the one probe that survived the
    2026-05-01 incident and that property must not regress."""

    def test_dig_spawn_failure_falls_back_to_getaddrinfo(self, monkeypatch):
        def fake_run_cmd(*a, **kw):
            raise app.SpawnFailureError("BlockingIOError: EAGAIN")
        monkeypatch.setattr(app, "run_cmd", fake_run_cmd)

        # Stub getaddrinfo so we don't touch the network.
        monkeypatch.setattr(app.socket, "getaddrinfo",
                            lambda host, port: [(2, 1, 6, "", ("1.2.3.4", 0))])
        result = app.run_dns("example.com")
        assert result["success"] is True
        assert "1.2.3.4" in result["answers"]


class TestSpawnFailureResultHelper:
    def test_includes_target_and_spawn_failure_flag(self):
        exc = BlockingIOError(errno.EAGAIN, "Resource temporarily unavailable")
        out = app._spawn_failure_result("ping", {"target": "8.8.8.8"}, exc)
        assert out["spawn_failure"] is True
        assert out["success"] is False
        assert out["target"] == "8.8.8.8"
        assert "BlockingIOError" in out["error"]
        assert out["command"] == "ping"

    def test_picks_url_when_no_target(self):
        exc = RuntimeError("can't start new thread")
        out = app._spawn_failure_result(
            "http_test", {"url": "https://example.com"}, exc)
        assert out["url"] == "https://example.com"
        assert "target" not in out

    def test_picks_host_when_no_target_or_url(self):
        exc = BlockingIOError()
        out = app._spawn_failure_result("tcp_time", {"host": "example.com"}, exc)
        assert out["host"] == "example.com"

    def test_no_target_field_when_no_known_key(self):
        exc = BlockingIOError()
        out = app._spawn_failure_result("speedtest", {}, exc)
        assert "target" not in out
        assert "host" not in out
        assert out["spawn_failure"] is True
