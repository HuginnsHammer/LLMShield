"""Environment-backed service configuration."""
from dataclasses import dataclass
import os
from typing import Literal


def _flag(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _policy_mode() -> Literal["enforce", "monitor"]:
    value = os.getenv("LLMSHIELD_POLICY_MODE", "enforce").strip().lower()
    if value not in {"enforce", "monitor"}:
        raise ValueError("LLMSHIELD_POLICY_MODE must be 'enforce' or 'monitor'")
    return value  # type: ignore[return-value]


@dataclass(frozen=True)
class Settings:
    audit_db_path: str = os.getenv("LLMSHIELD_AUDIT_DB", "llmshield-audit.sqlite3")
    max_body_bytes: int = int(os.getenv("LLMSHIELD_MAX_BODY_BYTES", "262144"))
    require_api_key: bool = _flag("LLMSHIELD_REQUIRE_API_KEY", False)
    api_key: str = os.getenv("LLMSHIELD_API_KEY", "")
    policy_mode: Literal["enforce", "monitor"] = _policy_mode()


settings = Settings()
