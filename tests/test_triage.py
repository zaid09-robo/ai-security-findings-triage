import pytest

from app.models.finding import Finding
from app.services.triage import triage_finding


def test_triage_finding():
    finding = Finding(
        id="F-100",
        title="SQL Injection",
        description="User input reaches a SQL query.",
        source="Burp Suite",

        impact=5,
        exploitability=4,
        exposure=4,
        privilege_requirement=2,

        asset_criticality=4,
        active_exploitation=4,

        evidence_strength=5,
        reproducibility=4,
        detection_reliability=4,
        context_consistency=4,
    )

    result = triage_finding(finding)

    assert result.severity_score == 24
    assert result.severity.value == "Critical"

    assert result.priority_score == 17
    assert result.priority.value == "P1"

    assert result.confidence_score == 22
    assert result.confidence.value == "High"

    assert result.priority_reason == (
        "P1 — internet-facing critical asset with confirmed exploitation."
    )


def test_triage_rejects_missing_inputs():
    finding = Finding(
        id="F-101",
        title="Incomplete Finding",
        description="Missing scoring data.",
        source="Burp Suite",
    )

    with pytest.raises(ValueError, match="Missing required triage inputs"):
        triage_finding(finding)