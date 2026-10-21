from .models import ChatMessage


async def complete_mock(model: str, messages: list[ChatMessage]) -> str:
    """Deterministic local adapter for development and policy testing."""
    last_user = next((m.content for m in reversed(messages) if m.role == "user"), "")
    return f"[mock:{model}] Received your message ({len(last_user)} characters). Configure an upstream provider for generated answers."
