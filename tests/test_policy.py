from typing import Literal

from llmshield.models import Finding
from llmshield.policy import apply_mode, decide


def finding(action: Literal["allow", "redact", "block", "review"]) -> Finding:
    return Finding(
        detector="test",
        category="prompt_injection" if action == "block" else "pii",
        severity="high" if action == "block" else "medium",
        message="synthetic test finding",
        action=action,
    )


def test_policy_precedence_block_then_review_then_redact():
    assert decide([finding("redact"), finding("block")]) == "block"
    assert decide([finding("redact"), finding("review")]) == "review"
    assert decide([finding("redact")]) == "redact"
    assert decide([]) == "allow"


def test_monitor_mode_does_not_enforce_but_keeps_findings():
    findings = [finding("block")]
    detector_decision = decide(findings)
    assert detector_decision == "block"
    assert apply_mode(detector_decision, "monitor") == "allow"
    assert findings[0].action == "block"


def test_enforce_mode_keeps_detector_decision():
    assert apply_mode("block", "enforce") == "block"
