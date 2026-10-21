import pytest

from llmshield.config import _policy_mode


def test_policy_mode_defaults_to_enforce(monkeypatch):
    monkeypatch.delenv("LLMSHIELD_POLICY_MODE", raising=False)
    assert _policy_mode() == "enforce"


def test_policy_mode_accepts_monitor(monkeypatch):
    monkeypatch.setenv("LLMSHIELD_POLICY_MODE", "monitor")
    assert _policy_mode() == "monitor"


def test_policy_mode_rejects_unknown_value(monkeypatch):
    monkeypatch.setenv("LLMSHIELD_POLICY_MODE", "observe")
    with pytest.raises(ValueError, match="LLMSHIELD_POLICY_MODE"):
        _policy_mode()
