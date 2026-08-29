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

def test_triage_populates_impact_summary_and_owasp():
    finding = Finding(
        id="F-102",
        title="Broken Access Control",
        description="A user can access another user's resource.",
        source="Burp Suite",

        impact=5,
        exploitability=4,
        exposure=4,
        privilege_requirement=3,

        asset_criticality=4,
        active_exploitation=3,

        evidence_strength=5,
        reproducibility=4,
        detection_reliability=4,
        context_consistency=4,
    )

    result = triage_finding(finding)

    assert result.impact_summary == (
        "Don't fix this and an attacker could compromise critical data or systems."
    )

    assert result.owasp_category == "A01:2025 Broken Access Control"


def test_triage_low_confidence():
    finding = Finding(
        id="F-103",
        title="Security Misconfiguration",
        description="Debug information is exposed.",
        source="Burp Suite",

        impact=2,
        exploitability=2,
        exposure=2,
        privilege_requirement=2,

        asset_criticality=2,
        active_exploitation=1,

        evidence_strength=2,
        reproducibility=2,
        detection_reliability=2,
        context_consistency=3,
    )

    result = triage_finding(finding)

    assert result.confidence_score == 11
    assert result.confidence.value == "Low"


def test_triage_updates_original_finding():
    finding = Finding(
        id="F-104",
        title="SQL Injection",
        description="User input reaches a SQL query.",
        source="Burp Suite",

        impact=5,
        exploitability=5,
        exposure=4,
        privilege_requirement=4,

        asset_criticality=4,
        active_exploitation=4,

        evidence_strength=5,
        reproducibility=4,
        detection_reliability=4,
        context_consistency=4,
    )

    result = triage_finding(finding)

    assert result is finding
    assert finding.severity_score == 28
    assert finding.severity.value == "Critical"
    assert finding.priority_score == 17
    assert finding.priority.value == "P1"
    assert finding.confidence_score == 22
    assert finding.confidence.value == "High"