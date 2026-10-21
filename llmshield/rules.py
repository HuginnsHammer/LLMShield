"""Validated YAML policy rules, kept separate from detector implementations."""
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .models import Action

Category = Literal["prompt_injection", "pii", "secret", "policy"]
Severity = Literal["low", "medium", "high", "critical"]
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class CategoryRule(BaseModel):
    """Action and minimum finding severity for one category."""

    model_config = ConfigDict(extra="forbid")

    action: Action
    minimum_severity: Severity = "low"


class PolicyFile(BaseModel):
    """User-supplied policy document. Omitted categories keep safe defaults."""

    model_config = ConfigDict(extra="forbid")

    categories: dict[Category, CategoryRule] = Field(default_factory=dict)


DEFAULT_POLICY_RULES: dict[Category, CategoryRule] = {
    "prompt_injection": CategoryRule(action="block", minimum_severity="low"),
    "pii": CategoryRule(action="redact", minimum_severity="low"),
    "secret": CategoryRule(action="block", minimum_severity="low"),
    "policy": CategoryRule(action="review", minimum_severity="low"),
}


def load_policy_rules(path: str | None = None) -> dict[Category, CategoryRule]:
    """Load and validate YAML rules; invalid files fail closed with a clear error."""
    rules = dict(DEFAULT_POLICY_RULES)
    if not path:
        return rules

    try:
        document = yaml.safe_load(Path(path).expanduser().read_text(encoding="utf-8"))
        parsed = PolicyFile.model_validate(document)
    except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
        raise ValueError(f"Unable to load valid LLMShield policy file: {path}") from exc

    rules.update(parsed.categories)
    return rules


def action_for(
    category: Category,
    severity: Severity,
    rules: dict[Category, CategoryRule] | None = None,
) -> Action:
    """Resolve the configured action, ignoring findings below its severity threshold."""
    selected = (rules or DEFAULT_POLICY_RULES)[category]
    if _SEVERITY_RANK[severity] < _SEVERITY_RANK[selected.minimum_severity]:
        return "allow"
    return selected.action
