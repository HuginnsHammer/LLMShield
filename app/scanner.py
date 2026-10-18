import re
from app.models import Finding, ScanResult

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
    re.compile(r"reveal\s+(the\s+)?(system prompt|hidden instructions)", re.I),
    re.compile(r"(developer|system)\s+message\s*:", re.I),
    re.compile(r"you are now\s+(in )?(developer|admin|unrestricted)\s+mode", re.I),
    re.compile(r"bypass\s+(all\s+)?(safety|security|policy)\s+(rules|filters)", re.I),
]
PII_PATTERNS = [
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("phone", re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)")),
]
SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("api_key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
]

def scan_text(text: str) -> ScanResult:
    findings: list[Finding] = []
    for pattern in INJECTION_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(Finding(detector="heuristic_injection", category="prompt_injection", severity="high", message="Possible instruction override or prompt extraction attempt.", action="block", start=match.start(), end=match.end()))
    for label, pattern in PII_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(Finding(detector="regex_pii", category="pii", severity="medium", message=f"Possible {label} detected.", action="redact", start=match.start(), end=match.end()))
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(Finding(detector="regex_secret", category="secret", severity="critical", message=f"Possible {label} detected.", action="block", start=match.start(), end=match.end()))
    sanitized = text
    spans = sorted(((f.start, f.end) for f in findings if f.category == "pii" and f.start is not None and f.end is not None), reverse=True)
    for start, end in spans:
        sanitized = sanitized[:start] + "[REDACTED]" + sanitized[end:]
    return ScanResult(findings=findings, sanitized_text=sanitized, blocked=any(f.action == "block" for f in findings), review_required=any(f.action == "review" for f in findings))
