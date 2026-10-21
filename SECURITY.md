# Security policy

## Supported scope

LLMShield is an early-stage project. There is no guarantee of production-grade security or a formal support SLA. Please report suspected vulnerabilities privately to the repository owner through GitHub's private vulnerability reporting feature, if enabled, or by direct private contact. Do not publish exploit details or secrets in a public issue.

## Deployment guidance

- Keep the service bound to loopback or a trusted private network unless a hardened reverse proxy is in front.
- Use a strong, unique API key and protect it as a secret.
- Do not enable remote provider forwarding in this version.
- Treat findings as potentially sensitive metadata and restrict audit access.
- Use TLS, rate limits, request and response size limits, outbound network restrictions, dependency scanning, and log-retention controls in any exposed deployment.
- Remember that heuristic scanning is not a security boundary and can be bypassed.
