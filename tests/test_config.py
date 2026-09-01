from app.services import config


def test_ollama_configuration_values_are_valid():
    assert isinstance(config.OLLAMA_HOST, str)
    assert config.OLLAMA_HOST.startswith(("http://", "https://"))

    assert isinstance(config.OLLAMA_MODEL, str)
    assert config.OLLAMA_MODEL.strip()

    assert isinstance(config.OLLAMA_TIMEOUT, int)
    assert config.OLLAMA_TIMEOUT > 0
