import hmac
import time
import uuid
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from . import __version__
from .audit import AuditStore
from .config import settings
from .models import ChatRequest, ChatResponse, HealthResponse
from .policy import apply_mode, decide
from .provider import complete_mock
from .scanner import scan_text

app = FastAPI(title="LLMShield", version=__version__)
audit = AuditStore(settings.audit_db_path)


@app.middleware("http")
async def request_limits(request: Request, call_next):
    size = request.headers.get("content-length", "")
    if size.isdigit() and int(size) > settings.max_body_bytes:
        return JSONResponse(status_code=413, content={"detail": "Request body too large."})
    return await call_next(request)


def _authorized(provided: str | None) -> bool:
    expected = settings.api_key
    if not expected or not provided:
        return False
    return hmac.compare_digest(provided, expected)


@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok")


@app.post("/v1/chat/completions", response_model=ChatResponse)
async def chat_completions(payload: ChatRequest, x_api_key: str | None = Header(default=None)):
    request_id = str(uuid.uuid4())
    if settings.require_api_key and not _authorized(x_api_key):
        raise HTTPException(status_code=401, detail="Missing or invalid gateway API key.")
    if payload.provider_url is not None or payload.provider_api_key is not None:
        raise HTTPException(status_code=403, detail="Upstream provider forwarding is disabled; only the local mock provider is available.")

    safe_messages = []
    findings = []
    for message in payload.messages:
        result = scan_text(message.content, settings.policy_rules)
        findings.extend(result.findings)
        safe_messages.append(message.model_copy(update={"content": result.sanitized_text}))

    decision = apply_mode(decide(findings), settings.policy_mode)
    provider = "mock"
    if decision == "block":
        answer = "Request blocked by LLMShield policy."
    elif decision == "review":
        answer = "Request held for manual review; no provider was called."
    else:
        answer = await complete_mock(payload.model, safe_messages)
        output = scan_text(answer, settings.policy_rules)
        findings.extend(output.findings)
        output_decision = apply_mode(decide(findings), settings.policy_mode)
        if output_decision in ("block", "review") and settings.policy_mode == "enforce":
            decision = output_decision
            answer = (
                "Response blocked by LLMShield policy."
                if decision == "block"
                else "Response held for manual review; no response content was returned."
            )
        else:
            answer = output.sanitized_text
            decision = output_decision

    event_id = await run_in_threadpool(audit.record, request_id, decision, provider, findings)
    # OpenAI-compatible envelope. Usage is a documented estimate for the mock provider,
    # not tokenizer-exact accounting; this build intentionally does not implement streaming.
    prompt_chars = sum(len(m.content) for m in payload.messages)
    completion_chars = len(answer)
    prompt_tokens = (prompt_chars + 3) // 4
    completion_tokens = (completion_chars + 3) // 4
    return ChatResponse(
        id=f"chatcmpl-{request_id.replace('-', '')}",
        created=int(time.time()),
        model=payload.model,
        choices=[{"index": 0, "message": {"role": "assistant", "content": answer}, "finish_reason": "stop"}],
        usage={"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens, "total_tokens": prompt_tokens + completion_tokens},
        request_id=request_id,
        decision=decision,
        findings=findings,
        provider=provider,
        audit_event_id=event_id,
    )


@app.get("/admin/audit")
async def audit_events(limit: int = 50, x_api_key: str | None = Header(default=None)):
    if not _authorized(x_api_key):
        raise HTTPException(status_code=401, detail="Valid LLMSHIELD_API_KEY is required.")
    events = await run_in_threadpool(audit.list_events, limit)
    return {"events": events}


@app.get("/admin/metrics")
async def audit_metrics(limit: int = 200, x_api_key: str | None = Header(default=None)):
    """Return aggregate counts from recent metadata-only audit events."""
    if not _authorized(x_api_key):
        raise HTTPException(status_code=401, detail="Valid LLMSHIELD_API_KEY is required.")
    events = await run_in_threadpool(audit.list_events, limit)
    decisions: dict[str, int] = {}
    categories: dict[str, int] = {}
    severities: dict[str, int] = {}
    for event in events:
        decision = event.get("decision", "unknown")
        decisions[decision] = decisions.get(decision, 0) + 1
        for finding in event.get("findings", []):
            category = finding.get("category", "unknown")
            severity = finding.get("severity", "unknown")
            categories[category] = categories.get(category, 0) + 1
            severities[severity] = severities.get(severity, 0) + 1
    return {
        "events_analyzed": len(events),
        "limit": max(1, min(limit, 200)),
        "decision_counts": decisions,
        "category_counts": categories,
        "severity_counts": severities,
    }
