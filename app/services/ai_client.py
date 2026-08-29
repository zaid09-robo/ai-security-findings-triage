from typing import Protocol


class AIClient(Protocol):
    def generate(self, prompt: str) -> dict:
        ...