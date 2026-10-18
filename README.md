# LLMShield

LLMShield is a lightweight security gateway that validates requests, inspects messages, applies a central policy decision, inspects provider output, and records privacy-conscious audit events.

> **Status:** early implementation. The gateway API, heuristic scanners, policy engine, mock provider, React dashboard, and initial tests are in place. This is not a certified security product.

## Features

- FastAPI chat endpoint and health check.
- Heuristic checks for common prompt-injection phrases, PII patterns, and selected secrets.
- Central policy precedence: block, review, redact, allow.
- PII redaction and response inspection.
- Deterministic mock provider; no external inference by default.
- React/Vite dashboard with live API request inspection and findings.
- SQLite audit metadata without raw prompt/response storage.
- Optional shared-key authentication, Docker Compose, and CI.

## Backend quick start

Requires Python 3.11 or newer.

    python -m venv .venv
    source .venv/bin/activate
    pip install -e '.[dev]'
    uvicorn app.main:app --reload

API docs: http://127.0.0.1:8000/docs

    ruff check .
    pytest --cov=app --cov-report=term-missing

## Dashboard development

Start the backend first, then in another terminal:

    cd frontend
    npm install
    npm run dev

Vite proxies API requests to the backend on localhost port 8000.

## Docker Compose

Set LLMSHIELD_API_KEY to a strong random value in your shell, then run:

    docker compose up --build

Dashboard: http://127.0.0.1:8080
API docs: http://127.0.0.1:8000/docs

## API

- GET /health
- POST /v1/chat/completions
- GET /admin/audit?limit=50 (requires the X-API-Key header matching LLMSHIELD_API_KEY)

Example request:

    {
      "model": "mock-model",
      "messages": [{"role": "user", "content": "Explain recursion briefly."}]
    }

Responses include a request ID, provider label, policy decision, findings, and audit event ID.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| LLMSHIELD_API_KEY | empty | Gateway/admin key |
| LLMSHIELD_REQUIRE_API_KEY | false | Require key on gateway endpoint |
| LLMSHIELD_ALLOW_REMOTE_PROVIDER | false | Reserved; forwarding is disabled |
| LLMSHIELD_AUDIT_DB | llmshield-audit.sqlite3 | SQLite path |
| LLMSHIELD_MAX_BODY_BYTES | 262144 | Maximum declared body size |

See .env.example. Never commit real credentials.

## Security limitations

- Detection is heuristic and can miss attacks or flag benign text.
- Real provider forwarding is disabled until a fixed upstream allowlist, SSRF protections, response validation, and integration tests are implemented.
- API-key authentication is a shared-secret baseline, not a complete identity system. Add rate limits, TLS, secret rotation, and deployment-specific access controls before production.
- The request-size guard relies on Content-Length; enforce limits at the reverse proxy too.
- Audit events omit raw content, but findings may still reveal sensitive categories.
- Redaction is not comprehensive anonymization. The review response is a hold message, not a working human-review queue.
- License selection is pending; do not assume unrestricted reuse.

## Roadmap

1. Configurable detector interfaces and policy rules.
2. Reproducible evaluation datasets and false-positive/false-negative metrics.
3. Secure audit browsing and a human-review workflow.
4. Provider adapters with strict upstream allowlists and rate limiting.
5. Dependency/container scanning and deployment hardening.
