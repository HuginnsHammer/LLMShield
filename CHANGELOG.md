# Changelog

## Unreleased

- Move the installable Python package to llmshield.
- Add Unicode normalization and additional selected secret detectors.
- Improve phone-number matching to avoid common date and numeric-reference false positives.
- Add defensive-example regression coverage.
- Return an OpenAI-style non-streaming chat-completion response envelope with additive policy metadata.
- Keep audit logs metadata-only and support persistent in-memory SQLite tests.
- Expand CI checks and add a synthetic evaluation harness.
- Improve dashboard typing, API-key support, and audit-event browsing.

## 0.1.0

- Initial FastAPI gateway, heuristic scanner, policy engine, mock provider, audit store, dashboard, and Docker setup.
