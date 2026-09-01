import json

import httpx

from app.services.config import (
    OLLAMA_HOST,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT,
)


AI_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "string",
        },
        "attack_scenario": {
            "type": "string",
        },
        "technical_explanation": {
            "type": "string",
        },
        "remediation_explanation": {
            "type": "string",
        },
        "analyst_notes": {
            "type": "string",
        },
    },
    "required": [
        "summary",
        "attack_scenario",
        "technical_explanation",
        "remediation_explanation",
        "analyst_notes",
    ],
}


class OllamaClient:
    """
    AI client for communicating with an Ollama server.
    """

    def __init__(
        self,
        host: str = OLLAMA_HOST,
        model: str = OLLAMA_MODEL,
        timeout: int = OLLAMA_TIMEOUT,
    ) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str) -> dict:
        """
        Send a prompt to Ollama and return the generated JSON object.
        """

        response = httpx.post(
            f"{self.host}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": AI_ANALYSIS_SCHEMA,
            },
            timeout=self.timeout,
        )

        response.raise_for_status()

        data = response.json()

        generated_response = data["response"]

        return json.loads(generated_response)
