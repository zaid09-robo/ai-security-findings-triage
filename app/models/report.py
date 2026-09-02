from pydantic import BaseModel, Field

from app.models.ai_analysis import AIAnalysis
from app.models.finding import Finding


class SecurityReport(BaseModel):
    finding: Finding
    ai_analysis: AIAnalysis
    markdown: str = Field(min_length=1)