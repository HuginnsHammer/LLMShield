import ipaddress
import socket
import uuid
from urllib.parse import urlparse
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from app.audit import AuditStore
from app.config import settings
from app.models import ChatRequest, ChatResponse, HealthResponse
from app.policy import decide
from app.provider import ProviderError, complete_mock, complete_openai_compatible
from app.scanner import scan_text

app = FastAPI(title='LLMShield', description='A policy-enforcing security gateway for LLM applications.', version='0.1.0')
audit = AuditStore(settings.audit_db_path)

def validate_provider_url(url: str) -> None:
    parsed = urlparse(url)
    local_hosts = {'localhost', '127.0.0.1', '::1'}
    if parsed.scheme != 'https' and parsed.hostname not in local_hosts:
        raise HTTPException(status_code=400, detail='Remote provider URLs must use HTTPS.')
    if not settings.allow_remote_provider and parsed.hostname not in local_hosts:
        raise HTTPException(status_code=403, detail='Remote provider URLs are disabled by configuration.')
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))}
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global and address not in {'127.0.0.1', '::1'}:
                raise HTTPException(status_code=400, detail='Provider URL resolves to a non-public address.')
    except socket.gaierror as exc:
        raise HTTPException(status_code=400, detail='Provider hostname could not be resolved.') from exc

@app.middleware('http')
async def request_limits(request: Request, call_next):
    length = request.headers.get('content-length', '')
    if length.isdigit() and int(length) > settings.max_body_bytes:
        return JSONResponse(status_code=413, content={'detail': 'Request body too large.'})
    return await call_next(request)

@app.get('/health', response_model=HealthResponse, tags=['operations'])
async def health() -> HealthResponse:
    return HealthResponse(status='ok')

@app.post('/v1/chat/completions', response_model=ChatResponse, tags=['gateway'])
async def chat_completions(payload: ChatRequest, x_api_key: str | None = Header(default=None)) -> ChatResponse:
    request_id = str(uuid.uuid4())
    if settings.require_api_key and (not settings.api_key or x_api_key != settings.api_key):
        raise HTTPException(status_code=401, detail='Missing or invalid gateway API key.')
    original_text = '\n'.join(message.content for message in payload.messages)
    scan = scan_text(original_text)
    decision = decide(scan.findings)
    provider_name = 'mock'
    response_text = ''
    if decision == 'block':
        response_text = 'Request blocked by LLMShield policy.'
    elif decision == 'review':
        response_text = 'Request held for manual review; no provider was called.'
    else:
        safe_messages = [message.model_copy(update={'content': scan.sanitized_text}) if message.role == 'user' else message for message in payload.messages]
        try:
            if payload.provider_url:
                validate_provider_url(str(payload.provider_url))
                provider_name = 'openai-compatible'
                response_text = await complete_openai_compatible(base_url=str(payload.provider_url), api_key=payload.provider_api_key.get_secret_value() if payload.provider_api_key else '', model=payload.model, messages=safe_messages, timeout=settings.upstream_timeout_seconds)
            else:
                response_text = await complete_mock(payload.model, safe_messages)
        except ProviderError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        output_scan = scan_text(response_text)
        scan.findings.extend(output_scan.findings)
        if output_scan.blocked:
            decision = 'block'
            response_text = 'Response blocked by LLMShield policy.'
        else:
            response_text = output_scan.sanitized_text
            decision = decide(scan.findings)
    event_id = audit.record(request_id, decision, provider_name, scan.findings, original_text, response_text)
    return ChatResponse(request_id=request_id, model=payload.model, content=response_text, decision=decision, findings=scan.findings, provider=provider_name, audit_event_id=event_id)

@app.get('/admin/audit', tags=['operations'])
async def audit_events(limit: int = 50, x_api_key: str | None = Header(default=None)):
    if not settings.api_key or x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail='Valid LLMSHIELD_API_KEY is required.')
    return {'events': audit.list_events(limit)}
