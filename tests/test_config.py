from app.services.config import (
    OLLAMA_HOST,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT,
)


def test_ollama_configuration_defaults():
    assert OLLAMA_HOST == "http://localhost:11434"
    assert OLLAMA_MODEL == "qwen2.5:7b"
    assert OLLAMA_TIMEOUT == 60
