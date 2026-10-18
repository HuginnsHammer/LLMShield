# LLMShield

LLMShield is a lightweight security gateway that sits between an application and an LLM provider. It validates requests, runs configurable inspection, applies a central policy decision, inspects provider output, and records privacy-conscious audit events.

> **Project status:** early implementation. The API, heuristic scanners, policy engine, mock adapter, optional OpenAI-compatible adapter, and initial tests are in place. This is not a certified security product. Regex detections are imperfect and must not be treated as a substitute for model-aware testing, threat modeling, or operational controls.

## What works today

- FastAPI service with a health endpoint and OpenAI-style chat endpoint.
- Heuristic checks for common prompt-injection phrases, email/phone-like PII, and selected API-key/private-key patterns.
- Central policy precedence: block, then review, then redact, then allow.
- Request PII redaction and response inspection before returning content.
- Local deterministic mock provider for development without external calls.
- Real provider forwarding is intentionally disabled in this initial build; requests that specify an upstream URL are rejected.
- SQLite audit events; request/response content is not stored by the audit store.
- Optional gateway API-key enforcement and request body limits.
- Tests for core scanner and gateway behavior.

## Quick start

Requires Python 3.11 or newer.

    python -m venv .venv
    source .venv/bin/activate
    pip install -e '.[dev]'
    uvicorn app.main:app --reload

Open http://127.0.0.1:8000/docs for the API docs. The default mock adapter does not contact an LLM provider; it exists to test gateway behavior safely.

Run tests:

    pytest

Run lint:

    ruff check .

## API

### Health

    GET /health

### Chat completions

    POST /v1/chat/completions
    Content-Type: application/json

Example body:

    {
      "model": "mock-model",
      "messages": [{"role": "user", "content": "Explain recursion briefly."}]
    }

Response includes a request ID, provider label, policy decision, findings, and audit event ID. Decisions are `allow`, `redact`, `block`, or `review`. A block/review decision does not call the provider.

### Audit events

    GET /admin/audit?limit=50

This endpoint requires the `X-API-Key` header to match `LLMSHIELD_API_KEY`. Configure a strong random key before using the admin endpoint. Do not expose the service publicly without authentication and deployment hardening.

## Configuration

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LLMSHIELD_API_KEY` | empty | Gateway/admin key |
| `LLMSHIELD_REQUIRE_API_KEY` | `false` | Require key on gateway endpoint |
| `LLMSHIELD_ALLOW_REMOTE_PROVIDER` | `false` | Permit non-local upstream URLs |
| `LLMSHIELD_AUDIT_DB` | `llmshield-audit.sqlite3` | SQLite path |
| `LLMSHIELD_MAX_BODY_BYTES` | `262144` | Maximum declared request body size |
| `LLMSHIELD_UPSTREAM_TIMEOUT` | `20` | Upstream timeout in seconds |

See `.env.example`. Do not commit real credentials.

## Docker

Set `LLMSHIELD_API_KEY` in your environment, then run:

    docker compose up --build

The compose configuration requires gateway authentication and keeps remote providers disabled by default. Change the sample key before use.

## Security notes and limitations

- Detection is heuristic. It can miss attacks and can flag benign text; never present it as a reliable semantic prompt-injection classifier.
- Provider URLs are disabled for remote hosts by default. Enabling remote providers increases SSRF and data-exfiltration risk; use a strict egress allowlist and network controls. DNS validation in application code alone is not a complete SSRF defense.
- Real provider forwarding is not enabled yet. Before enabling it, implement a fixed upstream allowlist, robust SSRF protections, provider-specific response validation, and integration tests.
- API-key authentication is a simple shared-secret baseline, not a complete identity or authorization system. Add rate limiting, TLS termination, secret rotation, and deployment-specific access controls before production use.
- Audit events store decision metadata and findings, not raw prompt/response content. Findings may still reveal sensitive categories; protect the database and restrict audit access.
- Redaction currently targets selected patterns only. It is not comprehensive anonymization.
- Human review is represented as a hold response; a reviewer workflow/UI is not yet implemented.
- No detector should independently authorize a request. The policy engine is the enforcement point, and provider calls must only happen after policy evaluation.

## Roadmap

1. Expand detector interfaces and policy configuration.
2. Add evaluation datasets, reproducible metrics, and false-positive/false-negative reporting.
3. Add a proper review queue and audit access controls.
4. Add provider adapters, safe upstream allowlists, rate limiting, and stronger integration tests.
5. Build a dashboard against the real API after backend behavior stabilizes.
6. Add CI, container scanning, dependency review, and deployment guidance.

## License

License selection is pending. Until a license is added, do not assume the code is licensed for unrestricted reuse.
