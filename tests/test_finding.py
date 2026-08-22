import pytest
from pydantic import ValidationError

from app.models.finding import Finding


def test_create_valid_finding():
    finding = Finding(
        id="F-001",
        title="SQL Injection",
        description="User input reaches a SQL query.",
        severity="High",
        priority="P1",
        confidence="High",
        source="Burp Suite",
    )

    assert finding.id == "F-001"
    assert finding.severity.value == "High"
    assert finding.priority.value == "P1"
    assert finding.confidence.value == "High"
    assert finding.source == "Burp Suite"


def test_invalid_severity_rejected():
    with pytest.raises(ValidationError):
        Finding(
            id="F-002",
            title="Test",
            description="Test finding",
            severity="Super Dangerous",
            priority="P1",
            confidence="High",
            source="Burp Suite",
        )