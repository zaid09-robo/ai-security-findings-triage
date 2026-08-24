from app.models.finding import Finding
from app.services.scoring import (
    calculate_confidence,
    calculate_priority,
    calculate_severity,
    generate_impact_summary,
    generate_priority_reason,
)

def classify_owasp(title: str) -> str | None:
    title_lower = title.lower()

    if "sql injection" in title_lower or "injection" in title_lower:
        return "A05:2025 Injection"

    if "broken access control" in title_lower:
        return "A01:2025 Broken Access Control"

    if "misconfiguration" in title_lower:
        return "A02:2025 Security Misconfiguration"

    if "cryptographic" in title_lower:
        return "A04:2025 Cryptographic Failures"

    if "authentication" in title_lower:
        return "A07:2025 Authentication Failures"

    return None

def triage_finding(finding: Finding) -> Finding:
    required_fields = {
        "impact": finding.impact,
        "exploitability": finding.exploitability,
        "exposure": finding.exposure,
        "privilege_requirement": finding.privilege_requirement,
        "asset_criticality": finding.asset_criticality,
        "active_exploitation": finding.active_exploitation,
        "evidence_strength": finding.evidence_strength,
        "reproducibility": finding.reproducibility,
        "detection_reliability": finding.detection_reliability,
        "context_consistency": finding.context_consistency,
    }

    missing_fields = [
        name for name, value in required_fields.items()
        if value is None
    ]

    if missing_fields:
        raise ValueError(
            f"Missing required triage inputs: {', '.join(missing_fields)}"
        )

    severity_score, severity = calculate_severity(
        impact=finding.impact,
        exploitability=finding.exploitability,
        exposure=finding.exposure,
        privilege_requirement=finding.privilege_requirement,
    )

    priority_score, priority = calculate_priority(
        severity=severity,
        exposure=finding.exposure,
        asset_criticality=finding.asset_criticality,
        active_exploitation=finding.active_exploitation,
    )

    confidence_score, confidence = calculate_confidence(
        evidence_strength=finding.evidence_strength,
        reproducibility=finding.reproducibility,
        detection_reliability=finding.detection_reliability,
        context_consistency=finding.context_consistency,
    )

    priority_reason = generate_priority_reason(
        priority=priority,
        exposure=finding.exposure,
        asset_criticality=finding.asset_criticality,
        active_exploitation=finding.active_exploitation,
    )

    impact_summary = generate_impact_summary(finding.impact)
    owasp_category = classify_owasp(finding.title)

    finding.severity_score = severity_score
    finding.severity = severity

    finding.priority_score = priority_score
    finding.priority = priority

    finding.confidence_score = confidence_score
    finding.confidence = confidence

    finding.priority_reason = priority_reason
    finding.impact_summary = impact_summary
    finding.owasp_category = owasp_category
    return finding