import os

from app.services.ai_client import AIClient
from app.services.mock_ai_client import MockAIClient
from app.services.ollama_client import OllamaClient


def get_ai_client(provider: str | None = None) -> AIClient:
    """
    Return the configured AI provider.

    Ollama is the default provider.
    Mock is available for testing and development.
    """

    selected_provider = (
        provider
        or os.getenv("AI_PROVIDER", "ollama")
    ).lower()

    if selected_provider == "ollama":
        return OllamaClient()

    if selected_provider == "mock":
        return MockAIClient()

    raise ValueError(
        f"Unsupported AI provider: {selected_provider}"
    )
