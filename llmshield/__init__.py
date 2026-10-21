"""LLMShield library and service package."""

__version__ = "0.2.0"


class Shield:
    """Small library facade for scanning untrusted text."""

    def scan(self, text: str):
        """Return a ScanResult containing findings and sanitized text."""
        from .scanner import scan_text

        return scan_text(text)
