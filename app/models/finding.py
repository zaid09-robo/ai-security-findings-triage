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

    severity: Severity
    priority: Priority
    confidence: Confidence

    source: str

    url: HttpUrl | None = None
    parameter: str | None = None

    evidence: str | None = None
    recommendation: str | None = None

    created_at: datetime = Field(default_factory=datetime.utcnow)
