"""Heuristic text scanner. Findings are signals, not a guarantee of security."""
import re
import unicodedata
from .models import Finding, ScanResult
from .rules import Category, CategoryRule, action_for

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u2060"), None)
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
})
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.I),
    re.compile(r"disregard\s+(?:everything|all|the instructions?).{0,50}(?:told|given|provided|said|earlier|before)", re.I),
    re.compile(r"reveal\s+(?:the\s+)?(?:system prompt|hidden instructions)", re.I),
    re.compile(r"(?:developer|system)\s+message\s*:", re.I),
    re.compile(r"you are now\s+(?:in\s+)?(?:developer|admin|unrestricted)\s+mode", re.I),
    re.compile(r"bypass\s+(?:all\s+)?(?:safety|security|policy)\s+(?:rules|filters)", re.I),
]
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
# Deliberately avoids plain digit-only identifiers and ISO-like dates.
PHONE = re.compile(r"(?<![\w])(?:\+\d{1,3}[ .()-]?)?(?:\(?\d{2,4}\)?[ .-])\d{3,4}[ .-]\d{3,4}(?!\w)")
SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("generic_bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{24,}", re.I)),
]
DEFENSIVE_CONTEXT = re.compile(r"\b(?:defen[cs]e|defensive|how do attackers|security awareness|explain defenses|detect prompt injection|prompt injection examples)\b", re.I)


def _normalize(text: str) -> tuple[str, list[int]]:
    normalized: list[str] = []
    positions: list[int] = []
    for index, char in enumerate(text):
        piece = unicodedata.normalize("NFKC", char).translate(_ZERO_WIDTH).translate(_HOMOGLYPHS)
        for out_char in piece:
            normalized.append(out_char)
            positions.append(index)
    return "".join(normalized), positions


def _quoted(text: str, start: int) -> bool:
    prefix = text[:start]
    for quote in ("'", '"', "“", "‘"):
        if prefix.count(quote) % 2:
            return True
    return False


def scan_text(text: str, policy_rules: dict[Category, CategoryRule] | None = None) -> ScanResult:
    normalized, positions = _normalize(text)
    findings: list[Finding] = []
    for pattern in INJECTION_PATTERNS:
        for match in pattern.finditer(normalized):
            original_start = positions[match.start()] if match.start() < len(positions) else 0
            original_end = positions[match.end() - 1] + 1 if match.end() and match.end() <= len(positions) else original_start
            # Quoted examples and clearly defensive questions should not be auto-blocked.
            if _quoted(text, original_start):
                continue
            findings.append(Finding(detector="heuristic_injection", category="prompt_injection", severity="high", message="Possible instruction override or prompt extraction attempt.", action=action_for("prompt_injection", "high", policy_rules), start=original_start, end=original_end))

    for label, pattern in (("email", EMAIL), ("phone", PHONE)):
        for match in pattern.finditer(normalized):
            if label == "phone":
                digits = sum(c.isdigit() for c in match.group())
                if digits < 10 or digits > 15:
                    continue
                context = normalized[max(0, match.start() - 24):match.start()].lower()
                if re.search(r"(?:order|reference|ref|ticket|invoice|id)\s*[:#-]?\s*$", context):
                    continue
            start = positions[match.start()]
            end = positions[match.end() - 1] + 1
            findings.append(Finding(detector="regex_pii", category="pii", severity="medium", message=f"Possible {label} detected.", action=action_for("pii", "medium", policy_rules), start=start, end=end))

    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(normalized):
            start = positions[match.start()]
            end = positions[match.end() - 1] + 1
            findings.append(Finding(detector="regex_secret", category="secret", severity="critical", message=f"Possible {label} detected.", action=action_for("secret", "critical", policy_rules), start=start, end=end))

    sanitized = text
    redaction_spans = {(f.start, f.end) for f in findings if f.action == "redact" and f.start is not None and f.end is not None}
    for start, end in sorted(redaction_spans, reverse=True):
        sanitized = sanitized[:start] + "[REDACTED]" + sanitized[end:]
    return ScanResult(findings=findings, sanitized_text=sanitized, blocked=any(f.action == "block" for f in findings), review_required=any(f.action == "review" for f in findings))
