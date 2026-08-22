from app.models.finding import Finding
from app.services.scoring import (
    calculate_confidence,
    calculate_priority,
    calculate_severity,
    generate_priority_reason,
)

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

    finding.severity_score = severity_score
    finding.severity = severity

    finding.priority_score = priority_score
    finding.priority = priority

    finding.confidence_score = confidence_score
    finding.confidence = confidence

    finding.priority_reason = priority_reason

    return finding