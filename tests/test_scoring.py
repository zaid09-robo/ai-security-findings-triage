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


def test_impact_ceiling():
    score, severity = calculate_severity(2, 5, 4, 4)

    assert score == 22
    assert severity == Severity.MEDIUM


def test_low_severity():
    score, severity = calculate_severity(1, 2, 2, 1)

    assert score == 9
    assert severity == Severity.LOW

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

    assert score == 16
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