import httpx
from app.models import ChatMessage

class ProviderError(RuntimeError):
    pass

async def complete_mock(model: str, messages: list[ChatMessage]) -> str:
    """Deterministic local adapter for development and policy testing."""
    last_user = next((m.content for m in reversed(messages) if m.role == "user"), "")
    return f"[mock:{model}] Received your message ({len(last_user)} characters). Configure an upstream provider for generated answers."

async def complete_openai_compatible(*, base_url: str, api_key: str, model: str, messages: list[ChatMessage], timeout: float) -> str:
    url = base_url.rstrip("/")
    if not url.endswith("/chat/completions"):
        url += "/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    payload = {"model": model, "messages": [m.model_dump() for m in messages]}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return str(data["choices"][0]["message"]["content"])
    except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
        raise ProviderError("Upstream provider request failed.") from exc
