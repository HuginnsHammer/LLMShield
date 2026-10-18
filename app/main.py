import uuid
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from app.audit import AuditStore
from app.config import settings
from app.models import ChatRequest, ChatResponse, HealthResponse
from app.policy import decide
from app.provider import ProviderError, complete_mock, complete_openai_compatible
from app.scanner import scan_text

app = FastAPI(title='LLMShield', version='0.1.0')
audit = AuditStore(settings.audit_db_path)

@app.middleware('http')
async def request_limits(request: Request, call_next):
    size = request.headers.get('content-length', '')
    if size.isdigit() and int(size) > settings.max_body_bytes:
        return JSONResponse(status_code=413, content={'detail': 'Request body too large.'})
    return await call_next(request)

@app.get('/health', response_model=HealthResponse)
async def health():
    return HealthResponse(status='ok')

@app.post('/v1/chat/completions', response_model=ChatResponse)
async def chat_completions(payload: ChatRequest, x_api_key: str | None = Header(default=None)):
    request_id = str(uuid.uuid4())
    if settings.require_api_key and (not settings.api_key or x_api_key != settings.api_key):
        raise HTTPException(status_code=401, detail='Missing or invalid gateway API key.')
    safe_messages = []
    findings = []
    originals = []
    for message in payload.messages:
        result = scan_text(message.content)
        findings.extend(result.findings)
        originals.append(message.content)
        content = result.sanitized_text if message.role == 'user' else message.content
        safe_messages.append(message.model_copy(update={'content': content}))
    decision = decide(findings)
    provider = 'mock'
    if decision == 'block':
        answer = 'Request blocked by LLMShield policy.'
    elif decision == 'review':
        answer = 'Request held for manual review; no provider was called.'
    else:
        try:
            if payload.provider_url:
                # Remote provider access stays disabled until a dedicated allowlist is implemented.
                raise HTTPException(status_code=403, detail='Upstream provider support is not enabled in this build.')
            answer = await complete_mock(payload.model, safe_messages)
        except ProviderError as exc:
            raise HTTPException(status_code=502, detail='Upstream provider request failed.') from exc
        output = scan_text(answer)
        findings.extend(output.findings)
        if output.blocked:
            decision = 'block'
            answer = 'Response blocked by LLMShield policy.'
        else:
            answer = output.sanitized_text
            decision = decide(findings)
    event_id = audit.record(request_id, decision, provider, findings, '\n'.join(originals), answer)
    return ChatResponse(request_id=request_id, model=payload.model, content=answer, decision=decision, findings=findings, provider=provider, audit_event_id=event_id)

@app.get('/admin/audit')
async def audit_events(limit: int = 50, x_api_key: str | None = Header(default=None)):
    if not settings.api_key or x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail='Valid LLMSHIELD_API_KEY is required.')
    return {'events': audit.list_events(limit)}
