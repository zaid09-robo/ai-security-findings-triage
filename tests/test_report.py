from app.models.ai_analysis import AIAnalysis
from app.models.finding import Finding
from app.models.report import SecurityReport


def test_security_report_model():
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

    ai_analysis = AIAnalysis(
        summary="SQL Injection exists.",
        attack_scenario="An attacker may inject SQL through the vulnerable parameter.",
        technical_explanation="User input is concatenated into a SQL query.",
        remediation_explanation="Use parameterized queries.",
        analyst_notes="Review the affected endpoint.",
        prompt_version="v1",
        finding_hash="abc123",
        status="success",
    )

    report = SecurityReport(
        finding=finding,
        ai_analysis=ai_analysis,
        markdown="# SQL Injection",
    )

    assert report.finding.id == "report-001"
    assert report.ai_analysis.status == "success"
    assert report.markdown == "# SQL Injection"