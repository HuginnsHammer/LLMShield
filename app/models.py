from typing import Literal
from pydantic import BaseModel, Field, HttpUrl, SecretStr, field_validator

class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = Field(min_length=1, max_length=100_000)

class ChatRequest(BaseModel):
    model: str = Field(default="mock-model", min_length=1, max_length=200)
    messages: list[ChatMessage] = Field(min_length=1, max_length=100)
    provider_url: HttpUrl | None = None
    provider_api_key: SecretStr | None = None
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def limit_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 30 or any(len(k) > 100 or len(v) > 500 for k, v in value.items()):
            raise ValueError("metadata exceeds allowed limits")
        return value

class Finding(BaseModel):
    detector: str
    category: Literal["prompt_injection", "pii", "secret", "policy"]
    severity: Literal["low", "medium", "high", "critical"]
    message: str
    action: Literal["allow", "redact", "block", "review"]
    start: int | None = None
    end: int | None = None

class ScanResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    sanitized_text: str
    blocked: bool = False
    review_required: bool = False

class ChatResponse(BaseModel):
    request_id: str
    model: str
    content: str
    decision: Literal["allow", "redact", "block", "review"]
    findings: list[Finding]
    provider: str
    audit_event_id: int | None = None

class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str = "LLMShield"
    version: str = "0.1.0"
