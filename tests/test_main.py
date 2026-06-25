import sys
from datetime import date

import pytest

from scanner import main


def test_main_exits_zero_when_no_vulnerabilities_are_found(monkeypatch, tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("safe-package==1.0.0\n", encoding="utf-8")

    def fake_run_trivy_scan(requirements_path):
        return {
            "status": "clean",
            "vulnerabilities": [],
        }

    monkeypatch.setattr(main, "run_trivy_scan", fake_run_trivy_scan)
    monkeypatch.setattr(
        sys,
        "argv",
        ["scanner.main", str(requirements)],
    )

    with pytest.raises(SystemExit) as exit_info:
        main.main()

    assert exit_info.value.code == 0


def test_main_exits_one_when_blocking_vulnerabilities_are_found(monkeypatch, tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("vulnerable-package==1.0.0\n", encoding="utf-8")

    def fake_run_trivy_scan(requirements_path):
        return {
            "status": "vulnerabilities_found",
            "vulnerabilities": [
                {
                    "id": "CVE-TEST-0001",
                    "package": "vulnerable-package",
                    "installed": "1.0.0",
                    "fixed": "1.0.1",
                    "severity": "MEDIUM",
                    "score": 5.0,
                    "title": "Example vulnerability",
                }
            ],
        }

    monkeypatch.setattr(main, "run_trivy_scan", fake_run_trivy_scan)
    monkeypatch.setattr(
        sys,
        "argv",
        ["scanner.main", str(requirements)],
    )

    with pytest.raises(SystemExit) as exit_info:
        main.main()

    assert exit_info.value.code == 1


def test_main_exits_two_when_scan_returns_error(monkeypatch, tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("example-package==1.0.0\n", encoding="utf-8")

    def fake_run_trivy_scan(requirements_path):
        return {
            "status": "error",
            "error": "Trivy database download failed",
            "vulnerabilities": [],
        }

    monkeypatch.setattr(main, "run_trivy_scan", fake_run_trivy_scan)
    monkeypatch.setattr(
        sys,
        "argv",
        ["scanner.main", str(requirements)],
    )

    with pytest.raises(SystemExit) as exit_info:
        main.main()

    assert exit_info.value.code == 2


def test_main_exits_zero_when_all_blocking_vulnerabilities_are_ignored(
    monkeypatch,
    tmp_path,
):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("vulnerable-package==1.0.0\n", encoding="utf-8")

    def fake_run_trivy_scan(requirements_path):
        return {
            "status": "vulnerabilities_found",
            "vulnerabilities": [
                {
                    "id": "CVE-TEST-0001",
                    "package": "vulnerable-package",
                    "installed": "1.0.0",
                    "fixed": "1.0.1",
                    "severity": "HIGH",
                    "score": 8.0,
                    "title": "Example vulnerability",
                }
            ],
        }

    def fake_load_ignore_list():
        return {
            "demo-project": {
                "CVE-TEST-0001": {
                    "expires": "2099-12-31",
                    "reason": "temporary accepted risk",
                }
            }
        }

    monkeypatch.setattr(main, "run_trivy_scan", fake_run_trivy_scan)
    monkeypatch.setattr(main, "load_ignore_list", fake_load_ignore_list)
    monkeypatch.setattr(
        sys,
        "argv",
        ["scanner.main", str(requirements), "--ignore-list"],
    )

    with pytest.raises(SystemExit) as exit_info:
        main.main()

    assert exit_info.value.code == 0


def test_load_ignore_list_returns_empty_dict_when_file_is_missing(tmp_path):
    missing_file = tmp_path / "missing-ignore-list.yaml"

    result = main.load_ignore_list(missing_file)

    assert result == {}


def test_load_ignore_list_returns_empty_dict_when_yaml_is_empty(tmp_path):
    ignore_list = tmp_path / "ignore-list.yaml"
    ignore_list.write_text("", encoding="utf-8")

    result = main.load_ignore_list(ignore_list)

    assert result == {}


def test_get_ignored_cves_includes_cve_before_expiry():
    ignore_list = {
        "demo-project": {
            "CVE-TEST-0001": {
                "expires": "2026-06-30",
                "reason": "temporary accepted risk",
            }
        }
    }

    result = main.get_ignored_cves(
        ignore_list,
        "demo-project",
        today=date(2026, 6, 25),
    )

    assert result == {"CVE-TEST-0001"}


def test_get_ignored_cves_includes_cve_on_expiry_date():
    ignore_list = {
        "demo-project": {
            "CVE-TEST-0001": {
                "expires": "2026-06-30",
            }
        }
    }

    result = main.get_ignored_cves(
        ignore_list,
        "demo-project",
        today=date(2026, 6, 30),
    )

    assert result == {"CVE-TEST-0001"}


def test_get_ignored_cves_excludes_cve_after_expiry_date():
    ignore_list = {
        "demo-project": {
            "CVE-TEST-0001": {
                "expires": "2026-06-30",
            }
        }
    }

    result = main.get_ignored_cves(
        ignore_list,
        "demo-project",
        today=date(2026, 7, 1),
    )

    assert result == set()


def test_get_ignored_cves_excludes_cve_with_invalid_expiry_date():
    ignore_list = {
        "demo-project": {
            "CVE-TEST-0001": {
                "expires": "not-a-date",
            }
        }
    }

    result = main.get_ignored_cves(
        ignore_list,
        "demo-project",
        today=date(2026, 6, 25),
    )

    assert result == set()


def test_get_ignored_cves_returns_empty_set_for_unknown_project():
    ignore_list = {
        "demo-project": {
            "CVE-TEST-0001": {
                "expires": "2026-06-30",
            }
        }
    }

    result = main.get_ignored_cves(
        ignore_list,
        "other-project",
        today=date(2026, 6, 25),
    )

    assert result == set()


def test_filter_vulnerabilities_splits_active_and_ignored_vulnerabilities():
    vulnerabilities = [
        {
            "id": "CVE-TEST-0001",
            "package": "example-package",
            "installed": "1.0.0",
            "fixed": "1.0.1",
            "severity": "HIGH",
            "score": 8.0,
            "title": "Ignored vulnerability",
        },
        {
            "id": "CVE-TEST-0002",
            "package": "another-package",
            "installed": "2.0.0",
            "fixed": "2.0.1",
            "severity": "MEDIUM",
            "score": 5.0,
            "title": "Active vulnerability",
        },
    ]

    active, ignored = main.filter_vulnerabilities(
        vulnerabilities,
        ignored_cves={"CVE-TEST-0001"},
    )

    assert active == [vulnerabilities[1]]
    assert ignored == [vulnerabilities[0]]
    