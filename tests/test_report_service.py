from app.models.ai_analysis import AIAnalysis
from app.models.finding import Finding
from app.services.triage import triage_finding
from app.services.report import (
    generate_markdown_report,
    generate_report,
)


def create_test_finding():
    finding = Finding(
        id="report-001",
        title="SQL Injection",
        description="User input is directly concatenated into a SQL query.",
        source="OWASP Test",
        impact=5,
        exploitability=5,
        exposure=4,
        privilege_requirement=1,
        asset_criticality=4,
        active_exploitation=4,
        evidence_strength=5,
        reproducibility=4,
        detection_reliability=4,
        context_consistency=4,
    )

    return triage_finding(finding)

def create_test_analysis():
    return AIAnalysis(
        summary="SQL Injection exists.",
        attack_scenario="An attacker may inject SQL through the vulnerable parameter.",
        technical_explanation="User input is concatenated into a SQL query.",
        remediation_explanation="Use parameterized queries.",
        analyst_notes="Review the affected endpoint.",
        prompt_version="v1",
        finding_hash="abc123",
        status="success",
    )


def test_generate_markdown_report():
    finding = create_test_finding()
    analysis = create_test_analysis()

    markdown = generate_markdown_report(
        finding=finding,
        analysis=analysis,
    )

    assert "# Security Finding Report" in markdown
    assert "SQL Injection" in markdown
    assert "Severity" in markdown
    assert finding.severity.value in markdown
    assert finding.priority.value in markdown
    assert finding.confidence.value in markdown
    assert "SQL Injection exists." in markdown
    assert "Use parameterized queries." in markdown

    # Report structure
    assert "## Finding" in markdown
    assert "## Triage Results" in markdown
    assert "## Finding Details" in markdown
    assert "## AI Analysis" in markdown
    assert "## AI Analysis Metadata" in markdown

    # Finding information
    assert "**Title:** SQL Injection" in markdown
    assert "**Source:** OWASP Test" in markdown

    # AI analysis content
    assert "An attacker may inject SQL" in markdown
    assert "User input is concatenated into a SQL query." in markdown


def test_generate_report():
    finding = create_test_finding()
    analysis = create_test_analysis()

    report = generate_report(
        finding=finding,
        analysis=analysis,
    )

    assert report.finding.id == "report-001"
    assert report.ai_analysis.status == "success"
    assert report.markdown
    assert "SQL Injection" in report.markdown