"""Policy decisions for detector findings."""
from typing import Literal

from .models import Finding

Decision = Literal["allow", "redact", "block", "review"]
PolicyMode = Literal["enforce", "monitor"]


def decide(findings: list[Finding]) -> Decision:
    """Apply stable precedence: block, review, redact, then allow."""
    actions = {finding.action for finding in findings}
    if "block" in actions:
        return "block"
    if "review" in actions:
        return "review"
    if "redact" in actions:
        return "redact"
    return "allow"


def apply_mode(decision: Decision, mode: PolicyMode) -> Decision:
    """In monitor mode, preserve findings but do not enforce their actions."""
    if mode == "monitor":
        return "allow"
    return decision
