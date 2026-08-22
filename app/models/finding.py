from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Priority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Finding(BaseModel):
    id: str
    title: str
    description: str

    severity: Severity | None = None
    priority: Priority | None = None
    confidence: Confidence | None = None

    source: str

    url: HttpUrl | None = None
    parameter: str | None = None

    evidence: str | None = None
    recommendation: str | None = None
    #severity input h 
    impact: int | None = None
    exploitability: int | None = None
    exposure: int | None = None
    privilege_requirement: int | None = None
    #priority input h ye
    asset_criticality: int | None = None
    active_exploitation: int | None = None
    #confidence input h 
    evidence_strength: int | None = None
    reproducibility: int | None = None
    detection_reliability: int | None = None
    context_consistency: int | None = None
     # Calculated scores h
    severity_score: int | None = None
    priority_score: int | None = None
    confidence_score: int | None = None

    # Human readable explanations h
    impact_summary: str | None = None
    priority_reason: str | None = None

    # OWASP classification
    owasp_category: str | None = None

    created_at: datetime = Field(default_factory=datetime.utcnow)
