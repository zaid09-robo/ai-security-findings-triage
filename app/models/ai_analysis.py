from typing import Literal

from pydantic import BaseModel, Field


class AIAnalysis(BaseModel):
    summary: str = Field(min_length=1)
    attack_scenario: str = Field(min_length=1)
    technical_explanation: str = Field(min_length=1)
    remediation_explanation: str = Field(min_length=1)
    analyst_notes: str = Field(min_length=1)

    prompt_version: str = Field(min_length=1)
    finding_hash: str = Field(min_length=1)

    status: Literal["success", "fallback"]