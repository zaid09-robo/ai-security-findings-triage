class MockAIClient:
    """
    Deterministic mock AI client used for testing.

    No external AI service is contacted.
    """

    def __init__(self) -> None:
        self.call_count = 0
        self.last_prompt: str | None = None

    def generate(self, prompt: str) -> dict:
        self.call_count += 1
        self.last_prompt = prompt

        return {
            "summary": (
                "The finding represents a potential security vulnerability."
            ),
            "attack_scenario": (
                "An attacker could exploit the vulnerable input "
                "under suitable conditions."
            ),
            "technical_explanation": (
                "The application processes attacker-controlled "
                "input in a security-sensitive context."
            ),
            "remediation_explanation": (
                "Apply appropriate security controls and validate "
                "or safely handle untrusted input."
            ),
            "analyst_notes": (
                "AI-generated analysis using the deterministic "
                "triage result."
            ),
        }
