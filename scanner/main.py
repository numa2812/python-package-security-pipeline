"""
scanner/main.py

Responsibility:
    Orchestrate the full security scan pipeline:
        1. Load the CVE ignore list (optional)
        2. Run Trivy via scan.py
        3. Filter ignored CVEs
        4. Classify results via classify.py
        5. Print a human-readable report
        6. Exit with code 0 (clean) or 1 (security gate failed)

Usage:
    python scanner/main.py <requirements_path> [--project <name>] [--ignore-list]

Examples:
    python scanner/main.py packages/requirements.txt
    python scanner/main.py packages/requirements.txt --ignore-list
    python scanner/main.py packages/requirements.txt --ignore-list --project demo-project
"""

import argparse
import logging
import sys
import yaml

from datetime import date
from pathlib import Path

from scanner.scan import run_trivy_scan
from scanner.classify import (
    classify_vulnerabilities,
    passes_security_gate,
    format_summary,
    SEVERITY_ORDER,
)

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,          # suppress INFO logs in normal CLI use
    format="%(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────
IGNORE_LIST_PATH = Path(__file__).parent / "ignore-list.yaml"

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}


# ──────────────────────────────────────────────────────────────
#  Ignore-list helpers
# ──────────────────────────────────────────────────────────────

def load_ignore_list(path: Path = IGNORE_LIST_PATH) -> dict:
    """
    Load and return the ignore-list YAML file.

    Returns an empty dict when the file does not exist,
    so callers never have to handle a missing file themselves.
    """
    if not path.is_file():
        logger.warning("Ignore list not found at %s — skipping.", path)
        return {}

    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get_ignored_cves(ignore_list: dict, project: str, today: date | None = None) -> set:
    """
    Return the set of CVE IDs that are currently valid (not expired)
    for the given project.

    Expiry logic:
        today <= expires  →  CVE is ignored  (within accepted-risk period)
        today >  expires  →  CVE re-surfaces  (accepted-risk period has ended)
    """
    ignored = set()
    today = today or date.today()

    for cve_id, entry in ignore_list.get(project, {}).items():
        try:
            expires = date.fromisoformat(str(entry.get("expires", "")))
        except ValueError:
            logger.warning("Invalid expires date for %s — not ignoring.", cve_id)
            continue

        if today <= expires:
            ignored.add(cve_id)
        else:
            print(f"  ⏰  {cve_id}: ignore period expired ({expires}) — re-detecting")

    return ignored


def filter_vulnerabilities(vulnerabilities: list, ignored_cves: set) -> tuple:
    """
    Split the vulnerability list into active and ignored entries.

    Returns:
        (active, ignored_list)
        active       : vulnerabilities that must be evaluated
        ignored_list : vulnerabilities suppressed by the ignore list
    """
    active = []
    ignored_list = []

    for vuln in vulnerabilities:
        if vuln["id"] in ignored_cves:
            ignored_list.append(vuln)
        else:
            active.append(vuln)

    return active, ignored_list


# ──────────────────────────────────────────────────────────────
#  Output helpers
# ──────────────────────────────────────────────────────────────

def print_header(requirements_path: str) -> None:
    print()
    print("=" * 62)
    print("  Python Package Security Pipeline")
    print(f"  Target : {requirements_path}")
    print("=" * 62)


def print_ignored(ignored_list: list) -> None:
    if not ignored_list:
        return
    print(f"\n  Ignored CVEs ({len(ignored_list)} suppressed by ignore list):")
    for vuln in ignored_list:
        print(f"  ⏭   {vuln['id']}: {vuln['package']} {vuln['installed']}")


def print_results(classified: dict) -> None:
    """Print a severity-grouped vulnerability report."""
    print(f"\n  {format_summary(classified)}\n")

    has_any = any(classified[level] for level in SEVERITY_ORDER)
    if not has_any:
        print("  ✅  No active vulnerabilities found.")
        return

    for level in SEVERITY_ORDER:
        vulns = classified[level]
        if not vulns:
            continue
        icon = SEVERITY_ICONS[level]
        for v in vulns:
            fixed = v["fixed"] if v["fixed"] != "unknown" else "no fix available"
            score = f"CVSS {v['score']:.1f}" if v["score"] > 0 else level
            print(
                f"  {icon}  {v['id']}: {v['package']} "
                f"{v['installed']} → {fixed}  ({score})"
            )


def print_gate_result(passed: bool) -> None:
    print()
    print("-" * 62)
    if passed:
        print("  ✅  Security Gate PASSED — no MEDIUM/HIGH/CRITICAL found.")
    else:
        print("  ❌  Security Gate FAILED — blocking vulnerabilities found.")
    print("-" * 62)
    print()


# ──────────────────────────────────────────────────────────────
#  CLI argument parser
# ──────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a requirements.txt for known vulnerabilities using Trivy.",
    )
    parser.add_argument(
        "requirements",
        help="Path to the requirements.txt file to scan.",
    )
    parser.add_argument(
        "--ignore-list",
        action="store_true",          # flag: present = True, absent = False
        help="Apply scanner/ignore-list.yaml to suppress accepted CVEs.",
    )
    parser.add_argument(
        "--project",
        default="demo-project",
        help="Project name used as key in ignore-list.yaml (default: demo-project).",
    )
    return parser


# ──────────────────────────────────────────────────────────────
#  Main orchestration
# ──────────────────────────────────────────────────────────────

def main() -> None:
    args = build_parser().parse_args()

    print_header(args.requirements)

    # Step 1 — Load ignore list (optional)
    ignored_cves: set = set()
    if args.ignore_list:
        print(f"\n  [Step 1] Loading ignore list for project '{args.project}'...")
        ignore_list = load_ignore_list()
        ignored_cves = get_ignored_cves(ignore_list, args.project)
        if ignored_cves:
            print(f"           {len(ignored_cves)} CVE(s) will be suppressed.")
        else:
            print("           No active ignore entries found.")
    else:
        print("\n  [Step 1] Ignore list disabled.")

    # Step 2 — Run Trivy scan
    print("\n  [Step 2] Running Trivy scan...")
    scan_result = run_trivy_scan(args.requirements)

    if scan_result["status"] == "error":
        print(f"\n  ❌  Scan error: {scan_result['error']}")
        sys.exit(2)         # exit code 2 = tool/configuration error (not a gate failure)

    total_found = len(scan_result["vulnerabilities"])
    print(f"           Trivy found {total_found} vulnerability/vulnerabilities.")

    # Step 3 — Apply ignore list
    active, ignored_list = filter_vulnerabilities(
        scan_result["vulnerabilities"], ignored_cves
    )
    print_ignored(ignored_list)

    # Step 4 — Classify active vulnerabilities
    print("\n  [Step 3] Classifying active vulnerabilities...")
    classified = classify_vulnerabilities(active)

    # Step 5 — Print report
    print_results(classified)

    # Step 6 — Security Gate
    passed = passes_security_gate(classified)
    print_gate_result(passed)

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
