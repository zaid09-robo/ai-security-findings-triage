import pytest

from app.services.ai_provider import get_ai_client
from app.services.mock_ai_client import MockAIClient
from app.services.ollama_client import OllamaClient


def test_default_provider_is_ollama(monkeypatch):
    monkeypatch.delenv("AI_PROVIDER", raising=False)

    client = get_ai_client()

    assert isinstance(client, OllamaClient)


def test_ollama_provider():
    client = get_ai_client("ollama")

    assert isinstance(client, OllamaClient)


def test_mock_provider():
    client = get_ai_client("mock")

    assert isinstance(client, MockAIClient)


def test_provider_from_environment(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "mock")

    client = get_ai_client()

    assert isinstance(client, MockAIClient)


def test_unknown_provider_raises_error():
    with pytest.raises(ValueError, match="Unsupported AI provider"):
        get_ai_client("unknown")
