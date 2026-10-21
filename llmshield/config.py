from dataclasses import dataclass
import os


def _flag(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    audit_db_path: str = os.getenv("LLMSHIELD_AUDIT_DB", "llmshield-audit.sqlite3")
    max_body_bytes: int = int(os.getenv("LLMSHIELD_MAX_BODY_BYTES", "262144"))
    require_api_key: bool = _flag("LLMSHIELD_REQUIRE_API_KEY", False)
    api_key: str = os.getenv("LLMSHIELD_API_KEY", "")


settings = Settings()
