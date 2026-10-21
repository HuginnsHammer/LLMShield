from pathlib import Path

import pytest

from llmshield.rules import action_for, load_policy_rules


def test_default_policy_is_safe():
    rules = load_policy_rules()
    assert action_for("prompt_injection", "high", rules) == "block"
    assert action_for("pii", "medium", rules) == "redact"
    assert action_for("secret", "critical", rules) == "block"


def test_yaml_overrides_action_and_threshold(tmp_path: Path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "categories:\n  pii:\n    action: review\n    minimum_severity: high\n",
        encoding="utf-8",
    )
    rules = load_policy_rules(str(policy))
    assert action_for("pii", "medium", rules) == "allow"
    assert action_for("pii", "high", rules) == "review"
    assert action_for("secret", "critical", rules) == "block"


@pytest.mark.parametrize(
    "contents",
    [
        "categories:\n  unknown_category:\n    action: block\n",
        "categories:\n  pii:\n    action: execute\n",
        "categories:\n  pii:\n    action: block\n    unexpected: true\n",
        "categories: [not, a, mapping]",
        "categories: {pii: [unterminated",
    ],
)
def test_invalid_yaml_policy_fails_closed(tmp_path: Path, contents: str):
    policy = tmp_path / "invalid.yaml"
    policy.write_text(contents, encoding="utf-8")
    with pytest.raises(ValueError, match="Unable to load valid LLMShield policy"):
        load_policy_rules(str(policy))
