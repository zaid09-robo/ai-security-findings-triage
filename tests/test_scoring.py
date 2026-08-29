from app.services.scoring import (
    Confidence,
    Priority,
    Severity,
    calculate_confidence,
    calculate_priority,
    calculate_severity,
    generate_priority_reason,
)


def test_critical_severity():
    score, severity = calculate_severity(5, 5, 4, 4)

    assert score == 28
    assert severity == Severity.CRITICAL


def test_high_severity():
    score, severity = calculate_severity(3, 4, 4, 3)

    assert score == 21
    assert severity == Severity.HIGH


# Phase 4 — Impact ceiling tests

def test_impact_1_caps_at_low():
    score, severity = calculate_severity(1, 5, 4, 4)

    assert score == 20
    assert severity == Severity.LOW


def test_impact_2_caps_at_medium():
    score, severity = calculate_severity(2, 5, 4, 4)

    assert score == 22
    assert severity == Severity.MEDIUM


def test_impact_3_caps_at_high():
    score, severity = calculate_severity(3, 5, 4, 4)

    assert score == 24
    assert severity == Severity.HIGH


def test_impact_4_allows_critical():
    score, severity = calculate_severity(4, 5, 4, 4)

    assert score == 26
    assert severity == Severity.CRITICAL


def test_impact_5_allows_critical():
    score, severity = calculate_severity(5, 5, 4, 4)

    assert score == 28
    assert severity == Severity.CRITICAL


def test_low_severity():
    score, severity = calculate_severity(1, 2, 2, 1)

    assert score == 9
    assert severity == Severity.LOW
# Phase 4 — Severity boundary tests

def test_severity_boundary_6_informational():
    score, severity = calculate_severity(1, 1, 1, 1)

    assert score == 6
    assert severity == Severity.INFORMATIONAL


def test_severity_boundary_7_low():
    score, severity = calculate_severity(1, 1, 1, 2)

    assert score == 7
    assert severity == Severity.LOW


def test_severity_boundary_12_medium():
    score, severity = calculate_severity(4, 1, 1, 1)

    assert score == 12
    assert severity == Severity.MEDIUM


def test_severity_boundary_17_medium():
    score, severity = calculate_severity(4, 1, 3, 4)

    assert score == 17
    assert severity == Severity.MEDIUM


def test_severity_boundary_18_high():
    score, severity = calculate_severity(4, 1, 4, 4)

    assert score == 18
    assert severity == Severity.HIGH


def test_severity_boundary_22_high():
    score, severity = calculate_severity(4, 3, 4, 4)

    assert score == 22
    assert severity == Severity.HIGH


def test_severity_boundary_23_critical():
    score, severity = calculate_severity(4, 4, 3, 4)

    assert score == 23
    assert severity == Severity.CRITICAL

def test_critical_priority_p1():
    score, priority = calculate_priority(
        Severity.CRITICAL,
        4,
        4,
        4,
    )

    assert score == 17
    assert priority == Priority.P1


def test_critical_isolated_priority_p3():
    score, priority = calculate_priority(
        Severity.CRITICAL,
        1,
        1,
        1,
    )

    assert score == 8
    assert priority == Priority.P3


def test_high_production_priority_p2():
    score, priority = calculate_priority(
        Severity.HIGH,
        4,
        3,
        1,
    )

    assert score == 12
    assert priority == Priority.P2


def test_active_exploitation_increases_priority():
    score, priority = calculate_priority(
        Severity.HIGH,
        4,
        4,
        4,
    )

# Phase 4 — Priority boundary tests

def test_priority_boundary_9_p3():
    score, priority = calculate_priority(
        Severity.CRITICAL,
        1,
        1,
        2,
    )

    assert score == 9
    assert priority == Priority.P3


def test_priority_boundary_10_p2():
    score, priority = calculate_priority(
        Severity.CRITICAL,
        1,
        1,
        3,
    )

    assert score == 10
    assert priority == Priority.P2


def test_priority_boundary_13_p2():
    score, priority = calculate_priority(
        Severity.CRITICAL,
        1,
        3,
        4,
    )

    assert score == 13
    assert priority == Priority.P2


def test_priority_boundary_14_p1():
    score, priority = calculate_priority(
        Severity.CRITICAL,
        1,
        4,
        4,
    )

    assert score == 14
    assert priority == Priority.P1

    
def test_priority_reason_p1():
    reason = generate_priority_reason(
        Priority.P1,
        4,
        4,
        4,
    )

    assert reason == (
        "P1 — internet-facing critical asset with confirmed exploitation."
    )


def test_priority_reason_p3():
    reason = generate_priority_reason(
        Priority.P3,
        1,
        1,
        1,
    )

    assert reason == (
        "P3 — isolated development or low-value asset with no known exploitation."
    )

def test_priority_reason_p2():
    reason = generate_priority_reason(
        Priority.P2,
        3,
        3,
        2,
    )

    assert reason == (
        "P2 — broadly accessible internal important production asset "
        "with a public exploit or credible threat."
    )


def test_priority_reason_p4():
    reason = generate_priority_reason(
        Priority.P4,
        2,
        2,
        1,
    )

    assert reason == (
        "P4 — restricted internal normal production/internal asset "
        "with no known exploitation."
    )

def test_high_confidence():
    score, confidence = calculate_confidence(
        5,
        4,
        4,
        4,
    )

    assert score == 22
    assert confidence == Confidence.HIGH


def test_medium_confidence():
    score, confidence = calculate_confidence(
        4,
        2,
        3,
        3,
    )

    assert score == 16
    assert confidence == Confidence.MEDIUM


def test_low_confidence():
    score, confidence = calculate_confidence(
        2,
        2,
        2,
        3,
    )

    assert score == 11
    assert confidence == Confidence.LOW

# Phase 4 — Confidence boundary tests

def test_confidence_boundary_11_low():
    score, confidence = calculate_confidence(
        1,
        1,
        4,
        4,
    )

    assert score == 11
    assert confidence == Confidence.LOW


def test_confidence_boundary_12_medium():
    score, confidence = calculate_confidence(
        1,
        2,
        4,
        4,
    )

    assert score == 12
    assert confidence == Confidence.MEDIUM


def test_confidence_boundary_17_medium():
    score, confidence = calculate_confidence(
        3,
        3,
        4,
        4,
    )

    assert score == 17
    assert confidence == Confidence.MEDIUM


def test_confidence_boundary_18_high():
    score, confidence = calculate_confidence(
        3,
        4,
        4,
        4,
    )

    assert score == 18
    assert confidence == Confidence.HIGH