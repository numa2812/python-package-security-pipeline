"""
scanner/classify.py

Responsibility:
    Group a flat vulnerability list (produced by scan.py) into
    severity buckets and evaluate the Security Gate outcome.

Public API:
    classify_vulnerabilities(vulnerabilities) -> dict
    passes_security_gate(classified)          -> bool
    format_summary(classified)                -> str
"""

import logging

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
#  CVSS v3.1 thresholds (NVD standard)
#  Reference: https://nvd.nist.gov/vuln-metrics/cvss
# ──────────────────────────────────────────────────────────────

THRESHOLDS = {
    "CRITICAL": 9.0,
    "HIGH":     7.0,
    "MEDIUM":   4.0,
    "LOW":      0.1,
}

# Security Gate fails for MEDIUM and above (score >= 4.0).
# This mirrors the design in the original thesis (section 4.3.2).
SECURITY_GATE_MINIMUM = "MEDIUM"

# Severity levels ordered from highest to lowest.
# Used to iterate in a consistent, meaningful order.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SCORABLE_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# ──────────────────────────────────────────────────────────────
#  Public API
# ──────────────────────────────────────────────────────────────

def classify_vulnerabilities(vulnerabilities: list) -> dict:
    """
    Group a flat vulnerability list into severity buckets.

    Classification strategy:
        1. If CVSS score > 0.0  → classify by score (numerically accurate)
        2. If CVSS score == 0.0 → fall back to Trivy's severity string
           (handles CVEs not yet scored in NVD)

    Args:
        vulnerabilities: List of vulnerability dicts from scan.py.

    Returns:
        {
            "CRITICAL": [ <vuln dict>, ... ],
            "HIGH":     [ <vuln dict>, ... ],
            "MEDIUM":   [ <vuln dict>, ... ],
            "LOW":      [ <vuln dict>, ... ],
            "UNKNOWN":  [ <vuln dict>, ... ],
        }
    """
    # Initialise all buckets so callers never have to check for missing keys.
    classified = {level: [] for level in SEVERITY_ORDER}

    for vuln in vulnerabilities:
        level = _determine_severity(vuln)
        classified[level].append(vuln)
        logger.debug(
            "Classified %s (%s, score=%.1f) as %s",
            vuln.get("id"), vuln.get("package"), vuln.get("score", 0.0), level,
        )

    _log_summary(classified)
    return classified


def passes_security_gate(classified: dict) -> bool:
    """
    Return True if no MEDIUM/HIGH/CRITICAL vulnerabilities exist.

    The gate blocks a merge when at least one vulnerability
    with CVSS >= 4.0 is present, following the thesis design.

    Args:
        classified: Output of classify_vulnerabilities().

    Returns:
        True  → no blocking vulnerabilities (merge allowed)
        False → blocking vulnerabilities found (merge blocked)
    """
    # Collect all severity levels that block the gate.
    blocking_levels = _levels_at_or_above(SECURITY_GATE_MINIMUM) + ["UNKNOWN"]

    for level in blocking_levels:
        if classified.get(level):
            logger.info(
                "Security gate FAILED: %d %s vulnerability/vulnerabilities found.",
                len(classified[level]), level,
            )
            return False

    logger.info("Security gate PASSED: no MEDIUM/HIGH/CRITICAL vulnerabilities.")
    return True


def format_summary(classified: dict) -> str:
    """
    Return a human-readable, single-line summary of classified results.

    Example output:
        "CRITICAL: 2 | HIGH: 1 | MEDIUM: 2 | LOW: 0"

    Args:
        classified: Output of classify_vulnerabilities().

    Returns:
        Formatted summary string.
    """
    parts = [f"{level}: {len(classified.get(level, []))}" for level in SEVERITY_ORDER]
    return " | ".join(parts)


# ──────────────────────────────────────────────────────────────
#  Internal helpers
# ──────────────────────────────────────────────────────────────

def _determine_severity(vuln: dict) -> str:
    """
    Determine the severity bucket for a single vulnerability.

    Primary:  CVSS score (when score > 0.0)
    Fallback: Trivy's severity string (when score == 0.0)
    Default:  "UNKNOWN" (when neither source is usable)
    """
    score = vuln.get("score", 0.0)

    if score > 0.0:
        return _severity_from_score(score)

    # Fallback: use severity string reported by Trivy
    severity_str = vuln.get("severity", "").upper()
    if severity_str in SEVERITY_ORDER:
        logger.debug(
            "No CVSS score for %s — using Trivy severity string: %s",
            vuln.get("id"), severity_str,
        )
        return severity_str

    logger.warning(
        "Could not determine severity for %s (score=0.0, severity='%s'). "
        "Defaulting to UNKNOWN.",
        vuln.get("id"), vuln.get("severity", ""),
    )
    return "UNKNOWN"


def _severity_from_score(score: float) -> str:
    """
    Map a CVSS score to a severity label using NVD thresholds.

        CRITICAL : score >= 9.0
        HIGH     : score >= 7.0
        MEDIUM   : score >= 4.0
        LOW      : score >= 0.1
    """
    for level in SCORABLE_SEVERITY_ORDER:          # iterate CRITICAL → HIGH → MEDIUM → LOW
        if score >= THRESHOLDS[level]:
            return level
    return "UNKNOWN"


def _levels_at_or_above(minimum: str) -> list:
    """
    Return severity levels that are equal to or more severe than `minimum`.

    Example:
        _levels_at_or_above("MEDIUM") → ["CRITICAL", "HIGH", "MEDIUM"]
    """
    minimum_index = SEVERITY_ORDER.index(minimum)
    return SEVERITY_ORDER[:minimum_index + 1]


def _log_summary(classified: dict) -> None:
    """Log a one-line breakdown after classification is complete."""
    summary = format_summary(classified)
    total = sum(len(v) for v in classified.values())
    logger.info("Classification complete — total: %d | %s", total, summary)
