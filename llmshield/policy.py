from typing import Literal
from .models import Finding

Decision = Literal["allow", "redact", "block", "review"]


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
