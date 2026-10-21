# Design decisions

## Heuristics before a model-based classifier

The first version uses regular expressions and explicit normalization because they are easy to inspect, test, and run locally without a model dependency. They are useful for known patterns but are not semantic understanding. False positives and false negatives are expected; the evaluation harness exists to make changes measurable rather than to imply complete coverage.

## No raw content in audit records

Audit records store timestamps, request IDs, policy decisions, provider labels, and structured detector findings. Raw prompts and responses can contain credentials, personal data, or customer secrets, so they are intentionally excluded from persistent logs. Findings can still reveal sensitive categories and should be access-controlled and retained only as long as operationally necessary.

## Forwarding disabled by default

A user-controlled provider URL creates an SSRF and credential-exfiltration risk. Remote forwarding stays disabled until upstream destinations are allowlisted and resolved/validated against private, loopback, link-local, and reserved address ranges; redirects and DNS rebinding are handled; outbound egress is restricted; response sizes and timeouts are bounded; and tests cover those guarantees. The included mock provider makes the inspection pipeline testable without external network access.

## OpenAI-style response envelope

The API uses the common non-streaming chat-completion response shape to reduce client integration friction. Security fields are additive. Token usage is an estimate for the mock implementation and should not be used for billing. Streaming and full SDK compatibility remain future work.

## Audit storage implementation

SQLite operations are synchronous internally and are dispatched to a threadpool from async request handlers. The in-memory test mode keeps one connection alive because each fresh SQLite :memory: connection otherwise creates a separate database.
