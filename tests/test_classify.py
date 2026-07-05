import pytest

from scanner.classify import (
    SEVERITY_ORDER,
    classify_vulnerabilities,
    format_summary,
    passes_security_gate,
)


def make_vulnerability(score, severity="UNKNOWN"):
    """Create a minimal vulnerability dictionary for tests."""
    return {
        "id": "CVE-TEST-0001",
        "package": "example-package",
        "installed": "1.0.0",
        "fixed": "1.0.1",
        "severity": severity,
        "score": score,
        "title": "Example vulnerability",
    }


@pytest.mark.parametrize(
    ("score", "expected_level"),
    [
        (0.1, "LOW"),
        (3.9, "LOW"),
        (4.0, "MEDIUM"),
        (6.9, "MEDIUM"),
        (7.0, "HIGH"),
        (8.9, "HIGH"),
        (9.0, "CRITICAL"),
        (10.0, "CRITICAL"),
    ],
)
def test_classifies_cvss_scores(score, expected_level):
    vulnerability = make_vulnerability(score)

    result = classify_vulnerabilities([vulnerability])

    assert result[expected_level] == [vulnerability]
    assert sum(len(items) for items in result.values()) == 1


def test_returns_all_severity_buckets_for_empty_input():
    result = classify_vulnerabilities([])

    assert list(result.keys()) == SEVERITY_ORDER
    assert all(result[level] == [] for level in SEVERITY_ORDER)


def test_uses_trivy_severity_when_cvss_score_is_missing():
    vulnerability = make_vulnerability(0.0, severity="high")

    result = classify_vulnerabilities([vulnerability])

    assert result["HIGH"] == [vulnerability]


def test_cvss_score_takes_precedence_over_trivy_severity():
    vulnerability = make_vulnerability(9.8, severity="LOW")

    result = classify_vulnerabilities([vulnerability])

    assert result["CRITICAL"] == [vulnerability]
    assert result["LOW"] == []


def test_classifies_as_unknown_when_score_and_severity_are_unknown():
    vulnerability = make_vulnerability(0.0, severity="UNKNOWN")

    result = classify_vulnerabilities([vulnerability])

    assert result["UNKNOWN"] == [vulnerability]
    assert result["LOW"] == []


@pytest.mark.parametrize(
    ("score", "expected_result"),
    [
        (0.1, True),
        (3.9, True),
        (4.0, False),
        (7.0, False),
        (9.0, False),
    ],
)
def test_security_gate_decision(score, expected_result):
    classified = classify_vulnerabilities([make_vulnerability(score)])

    result = passes_security_gate(classified)

    assert result is expected_result


def test_security_gate_fails_for_unknown_severity():
    classified = classify_vulnerabilities([
        make_vulnerability(0.0, severity="UNKNOWN")
    ])

    result = passes_security_gate(classified)

    assert result is False


def test_classifies_as_unknown_when_severity_string_is_unrecognized():
    vulnerability = make_vulnerability(0.0, severity="NOT_A_REAL_SEVERITY")

    result = classify_vulnerabilities([vulnerability])

    assert result["UNKNOWN"] == [vulnerability]
    assert result["LOW"] == []


def test_security_gate_passes_for_empty_input():
    classified = classify_vulnerabilities([])

    result = passes_security_gate(classified)

    assert result is True


def test_formats_summary_in_severity_order():
    vulnerabilities = [
        make_vulnerability(9.8),
        make_vulnerability(7.5),
        make_vulnerability(5.0),
        make_vulnerability(2.0),
        make_vulnerability(0.0, severity="UNKNOWN"),
    ]
    classified = classify_vulnerabilities(vulnerabilities)

    result = format_summary(classified)

    assert result == "CRITICAL: 1 | HIGH: 1 | MEDIUM: 1 | LOW: 1 | UNKNOWN: 1"