from typing import Literal
from app.models import Finding

Decision = Literal["allow", "redact", "block", "review"]

def decide(findings: list[Finding]) -> Decision:
    """Block takes precedence over review, which takes precedence over redaction."""
    actions = {finding.action for finding in findings}
    if "block" in actions:
        return "block"
    if "review" in actions:
        return "review"
    if "redact" in actions:
        return "redact"
    return "allow"
