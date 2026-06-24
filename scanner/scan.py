"""
scanner/scan.py

Responsibility:
    Run Trivy against a requirements.txt file and return
    a structured list of detected vulnerabilities.

This module has a single public function: run_trivy_scan().
Classification of results (CRITICAL / HIGH / ...) is handled
by classify.py, keeping each module focused on one task.
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
#  Public API
# ──────────────────────────────────────────────────────────────

def run_trivy_scan(requirements_path: str) -> dict:
    """
    Run Trivy against the given requirements.txt and return
    structured vulnerability data.

    Args:
        requirements_path: Path to the requirements.txt file to scan.

    Returns:
        On success:
            {
                "status": "clean" | "vulnerabilities_found",
                "vulnerabilities": [ <vulnerability dict>, ... ]
            }
        On error:
            {
                "status": "error",
                "error":  "<error message>",
                "vulnerabilities": []
            }

    Vulnerability dict structure:
        {
            "id":        str,   # e.g. "CVE-2020-1747"
            "package":   str,   # e.g. "PyYAML"
            "installed": str,   # e.g. "5.1"
            "fixed":     str,   # e.g. "5.3.1"
            "severity":  str,   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
            "score":     float, # CVSS v3 score, e.g. 9.8
            "title":     str,   # short description
        }
    """
    req_path = Path(requirements_path)

    if not req_path.is_file():
        logger.error("requirements.txt not found: %s", requirements_path)
        return {
            "status": "error",
            "error": f"File not found: {requirements_path}",
            "vulnerabilities": [],
        }

    # Use a temporary file so Trivy can write JSON output
    # without interfering with the console.
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = tmp.name

    cmd = [
        "trivy", "fs",
        "--scanners", "vuln",   # vulnerability scan only (no secret scan)
        "--format",   "json",   # machine-readable output
        "--output",   output_path,
        "--quiet",              # suppress progress bars in CI logs
        str(req_path),
    ]

    logger.info("Running Trivy: %s", " ".join(cmd))

    try:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            # Trivy is not installed or not on PATH
            return {
                "status": "error",
                "error": "Trivy not found. Please install Trivy: https://trivy.dev",
                "vulnerabilities": [],
            }

        # Without Trivy's --exit-code option, a completed scan returns 0 even
        # when vulnerabilities are found. Any non-zero code is therefore a
        # tool/configuration error; the Python security gate evaluates the
        # parsed findings separately in classify.py.
        if result.returncode != 0:
            error_message = result.stderr.strip() or "Trivy scan failed."
            return {
                "status": "error",
                "error": error_message,
                "vulnerabilities": [],
            }

        return _parse_trivy_json(output_path)
    finally:
        Path(output_path).unlink(missing_ok=True)


# ──────────────────────────────────────────────────────────────
#  Internal helpers (prefix _ = not part of the public API)
# ──────────────────────────────────────────────────────────────

def _best_cvss_score(vuln: dict) -> float:
    """Return the highest available CVSS score across all sources and versions."""
    scores = []
    for source in vuln.get("CVSS", {}).values():
        for key in ("V3Score", "V2Score"):
            score = source.get(key)
            if isinstance(score, (int, float)):
                scores.append(float(score))
    return max(scores, default=0.0)


def _parse_trivy_json(json_path: str) -> dict:
    """
    Parse the Trivy JSON output file into a flat vulnerability list.

    Trivy's JSON has a nested structure:
        Results[] -> Vulnerabilities[] -> individual CVE fields

    We flatten this into a simple list of dicts so that
    classify.py and main.py do not need to know about
    Trivy's internal format.
    """
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error("Failed to read Trivy output: %s", e)
        return {
            "status": "error",
            "error": f"Could not parse Trivy output: {e}",
            "vulnerabilities": [],
        }

    vulnerabilities = []

    for result in data.get("Results", []):
        # "Vulnerabilities" key is absent when no CVEs are found
        for vuln in result.get("Vulnerabilities") or []:
            vulnerabilities.append({
                "id":        vuln.get("VulnerabilityID", "UNKNOWN"),
                "package":   vuln.get("PkgName",          "unknown"),
                "installed": vuln.get("InstalledVersion",  "unknown"),
                "fixed":     vuln.get("FixedVersion",      "unknown"),
                "severity":  vuln.get("Severity",          "UNKNOWN"),
                "score":     _best_cvss_score(vuln),
                "title":     vuln.get("Title",             ""),
            })

    status = "vulnerabilities_found" if vulnerabilities else "clean"
    logger.info("Scan complete: %d vulnerability/vulnerabilities found.", len(vulnerabilities))

    return {
        "status": status,
        "vulnerabilities": vulnerabilities,
    }
