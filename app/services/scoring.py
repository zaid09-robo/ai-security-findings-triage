from enum import Enum


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

def calculate_severity(
    impact: int,
    exploitability: int,
    exposure: int,
    privilege_requirement: int,
) -> tuple[int, Severity]:
    raw_score = (
        (impact * 2)
        + (exploitability * 2)
        + exposure
        + privilege_requirement
    )

    if raw_score >= 23:
        severity = Severity.CRITICAL
    elif raw_score >= 18:
        severity = Severity.HIGH
    elif raw_score >= 12:
        severity = Severity.MEDIUM
    elif raw_score >= 7:
        severity = Severity.LOW
    else:
        severity = Severity.INFORMATIONAL

    severity_ceiling = {
        1: Severity.LOW,
        2: Severity.MEDIUM,
        3: Severity.HIGH,
        4: Severity.CRITICAL,
        5: Severity.CRITICAL,
    }

    maximum_severity = severity_ceiling[impact]

    severity_order = {
        Severity.INFORMATIONAL: 1,
        Severity.LOW: 2,
        Severity.MEDIUM: 3,
        Severity.HIGH: 4,
        Severity.CRITICAL: 5,
    }

    if severity_order[severity] > severity_order[maximum_severity]:
        severity = maximum_severity

    return raw_score, severity

def calculate_priority(
    severity: Severity,
    exposure: int,
    asset_criticality: int,
    active_exploitation: int,
) -> tuple[int, Priority]:
    severity_weight = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFORMATIONAL: 1,
    }

    priority_score = (
        severity_weight[severity]
        + exposure
        + asset_criticality
        + active_exploitation
    )

    if priority_score >= 14:
        priority = Priority.P1
    elif priority_score >= 10:
        priority = Priority.P2
    elif priority_score >= 7:
        priority = Priority.P3
    else:
        priority = Priority.P4

    return priority_score, priority
def generate_priority_reason(
    priority: Priority,
    exposure: int,
    asset_criticality: int,
    active_exploitation: int,
) -> str:
    exposure_text = {
        4: "internet-facing",
        3: "broadly accessible internal",
        2: "restricted internal",
        1: "isolated",
    }

    asset_text = {
        4: "critical asset",
        3: "important production asset",
        2: "normal production/internal asset",
        1: "development or low-value asset",
    }

    exploitation_text = {
        4: "confirmed exploitation",
        3: "strong evidence of exploitation attempts",
        2: "a public exploit or credible threat",
        1: "no known exploitation",
    }

    return (
        f"{priority.value} — "
        f"{exposure_text[exposure]} {asset_text[asset_criticality]} "
        f"with {exploitation_text[active_exploitation]}."
    )

def calculate_confidence(
    evidence_strength: int,
    reproducibility: int,
    detection_reliability: int,
    context_consistency: int,
) -> tuple[int, Confidence]:
    confidence_score = (
        (evidence_strength * 2)
        + reproducibility
        + detection_reliability
        + context_consistency
    )

    if confidence_score >= 18:
        confidence = Confidence.HIGH
    elif confidence_score >= 12:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.LOW

    return confidence_score, confidence

def generate_impact_summary(impact: int) -> str:
    summaries = {
        1: "Limited impact if exploited.",
        2: "An attacker could cause limited damage.",
        3: "An attacker could compromise part of the application.",
        4: "An attacker could cause major damage to the application or data.",
        5: "Don't fix this and an attacker could compromise critical data or systems.",
    }

    return summaries[impact]