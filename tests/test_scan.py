import json
import subprocess

from scanner import scan


def _requirements_file(tmp_path):
    """Create the smallest valid scan target needed by these unit tests."""
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("example-package==1.0.0\n", encoding="utf-8")
    return requirements


def _output_path_from(command):
    """Return the temporary JSON path passed after Trivy's --output flag."""
    return command[command.index("--output") + 1]


def test_returns_error_when_requirements_file_does_not_exist(tmp_path, monkeypatch):
    def unexpected_run(*args, **kwargs):
        raise AssertionError("Trivy must not run when the target file is missing")

    monkeypatch.setattr(scan.subprocess, "run", unexpected_run)

    result = scan.run_trivy_scan(str(tmp_path / "missing-requirements.txt"))

    assert result == {
        "status": "error",
        "error": f"File not found: {tmp_path / 'missing-requirements.txt'}",
        "vulnerabilities": [],
    }


def test_returns_helpful_error_when_trivy_is_not_installed(tmp_path, monkeypatch):
    requirements = _requirements_file(tmp_path)
    temporary_output = None

    def trivy_not_found(command, **kwargs):
        nonlocal temporary_output
        temporary_output = _output_path_from(command)
        raise FileNotFoundError

    monkeypatch.setattr(scan.subprocess, "run", trivy_not_found)

    result = scan.run_trivy_scan(str(requirements))

    assert result == {
        "status": "error",
        "error": "Trivy not found. Please install Trivy: https://trivy.dev",
        "vulnerabilities": [],
    }
    assert temporary_output is not None
    assert not scan.Path(temporary_output).exists()


def test_returns_trivy_stderr_for_nonzero_exit_code(tmp_path, monkeypatch):
    requirements = _requirements_file(tmp_path)
    temporary_output = None

    def failed_trivy(command, **kwargs):
        nonlocal temporary_output
        temporary_output = _output_path_from(command)
        return subprocess.CompletedProcess(
            command,
            returncode=1,
            stdout="",
            stderr="failed to download vulnerability DB\n",
        )

    monkeypatch.setattr(scan.subprocess, "run", failed_trivy)

    result = scan.run_trivy_scan(str(requirements))

    assert result == {
        "status": "error",
        "error": "failed to download vulnerability DB",
        "vulnerabilities": [],
    }
    assert temporary_output is not None
    assert not scan.Path(temporary_output).exists()


def test_uses_fallback_message_when_failed_trivy_has_no_stderr(tmp_path, monkeypatch):
    requirements = _requirements_file(tmp_path)

    def failed_trivy(command, **kwargs):
        return subprocess.CompletedProcess(
            command, returncode=2, stdout="", stderr=""
        )

    monkeypatch.setattr(scan.subprocess, "run", failed_trivy)

    result = scan.run_trivy_scan(str(requirements))

    assert result == {
        "status": "error",
        "error": "Trivy scan failed.",
        "vulnerabilities": [],
    }


def test_returns_clean_for_successful_scan_without_vulnerabilities(
    tmp_path, monkeypatch
):
    requirements = _requirements_file(tmp_path)
    temporary_output = None

    def successful_trivy(command, **kwargs):
        nonlocal temporary_output
        temporary_output = _output_path_from(command)
        scan.Path(temporary_output).write_text(
            json.dumps({"Results": []}), encoding="utf-8"
        )

        assert command[:2] == ["trivy", "fs"]
        assert command[-1] == str(requirements)
        assert kwargs == {"capture_output": True, "text": True}
        return subprocess.CompletedProcess(
            command, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(scan.subprocess, "run", successful_trivy)

    result = scan.run_trivy_scan(str(requirements))

    assert result == {"status": "clean", "vulnerabilities": []}
    assert temporary_output is not None
    assert not scan.Path(temporary_output).exists()


def test_scans_nonstandard_requirements_filename_as_requirements_txt(
    tmp_path, monkeypatch
):
    requirements = tmp_path / "vulnerable-requirements.txt"
    requirements.write_text("example-package==1.0.0\n", encoding="utf-8")

    def successful_trivy(command, **kwargs):
        scan_target = scan.Path(command[-1])
        output_path = _output_path_from(command)
        scan.Path(output_path).write_text(
            json.dumps({"Results": []}), encoding="utf-8"
        )

        assert scan_target.name == "requirements.txt"
        assert scan_target.read_text(encoding="utf-8") == "example-package==1.0.0\n"
        assert scan_target.parent != requirements.parent
        return subprocess.CompletedProcess(
            command, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(scan.subprocess, "run", successful_trivy)

    result = scan.run_trivy_scan(str(requirements))

    assert result == {"status": "clean", "vulnerabilities": []}


def test_parses_vulnerabilities_and_uses_highest_cvss_score(tmp_path, monkeypatch):
    requirements = _requirements_file(tmp_path)
    trivy_json = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-TEST-0001",
                        "PkgName": "example-package",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Severity": "HIGH",
                        "Title": "Example vulnerability",
                        "CVSS": {
                            "nvd": {"V3Score": 7.5, "V2Score": 5.0},
                            "vendor": {"V3Score": 8.2},
                        },
                    }
                ]
            }
        ]
    }

    def successful_trivy(command, **kwargs):
        output_path = _output_path_from(command)
        scan.Path(output_path).write_text(json.dumps(trivy_json), encoding="utf-8")
        return subprocess.CompletedProcess(
            command, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(scan.subprocess, "run", successful_trivy)

    result = scan.run_trivy_scan(str(requirements))

    assert result == {
        "status": "vulnerabilities_found",
        "vulnerabilities": [
            {
                "id": "CVE-TEST-0001",
                "package": "example-package",
                "installed": "1.0.0",
                "fixed": "1.0.1",
                "severity": "HIGH",
                "score": 8.2,
                "title": "Example vulnerability",
            }
        ],
    }


def test_returns_error_when_trivy_writes_invalid_json(tmp_path, monkeypatch):
    requirements = _requirements_file(tmp_path)

    def successful_trivy_with_invalid_output(command, **kwargs):
        output_path = _output_path_from(command)
        scan.Path(output_path).write_text("not-json", encoding="utf-8")
        return subprocess.CompletedProcess(
            command, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(
        scan.subprocess, "run", successful_trivy_with_invalid_output
    )

    result = scan.run_trivy_scan(str(requirements))

    assert result["status"] == "error"
    assert result["error"].startswith("Could not parse Trivy output:")
    assert result["vulnerabilities"] == []
