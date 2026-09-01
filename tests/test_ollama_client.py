import httpx

from app.services.ollama_client import OllamaClient


def test_ollama_client_returns_generated_json(monkeypatch):
    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "model": "qwen2.5:7b",
                "response": (
                    '{"summary":"SQL injection found.",'
                    '"attack_scenario":"Attacker injects SQL.",'
                    '"technical_explanation":"Input reaches a query.",'
                    '"remediation_explanation":"Use parameterized queries.",'
                    '"analyst_notes":"High-risk finding."}'
                ),
                "done": True,
            }

    def mock_post(*args, **kwargs):
        assert args[0] == "http://localhost:11434/api/generate"
        assert kwargs["json"]["model"] == "qwen2.5:7b"
        assert kwargs["json"]["stream"] is False
        assert kwargs["json"]["format"]["type"] == "object"
        assert set(kwargs["json"]["format"]["required"]) == {
            "summary",
            "attack_scenario",
            "technical_explanation",
            "remediation_explanation",
            "analyst_notes",
        }
        assert kwargs["timeout"] == 60

        return MockResponse()

    monkeypatch.setattr(httpx, "post", mock_post)

    client = OllamaClient(
        host="http://localhost:11434",
        model="qwen2.5:7b",
        timeout=60,
    )

    result = client.generate("Analyze this finding.")

    assert result["summary"] == "SQL injection found."
    assert result["attack_scenario"] == "Attacker injects SQL."
    assert result["technical_explanation"] == "Input reaches a query."
    assert result["remediation_explanation"] == "Use parameterized queries."
    assert result["analyst_notes"] == "High-risk finding."


def test_ollama_client_uses_custom_configuration(monkeypatch):
    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "response": '{"summary":"Test"}'
            }

    def mock_post(*args, **kwargs):
        assert args[0] == "http://example-ollama:11434/api/generate"
        assert kwargs["json"]["model"] == "custom-model"
        assert kwargs["timeout"] == 30

        return MockResponse()

    monkeypatch.setattr(httpx, "post", mock_post)

    client = OllamaClient(
        host="http://example-ollama:11434/",
        model="custom-model",
        timeout=30,
    )

    result = client.generate("Test prompt.")

    assert result == {"summary": "Test"}
