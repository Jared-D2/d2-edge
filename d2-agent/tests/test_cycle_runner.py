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
