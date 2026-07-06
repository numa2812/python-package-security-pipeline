# Python Package Security Pipeline

[![Security Scan](https://github.com/numa2812/python-package-security-pipeline/actions/workflows/security-scan.yml/badge.svg)](https://github.com/numa2812/python-package-security-pipeline/actions/workflows/security-scan.yml)

A demo project based on my Bachelor thesis on software supply chain security
for Python package provisioning.

> **Note on scan inputs:** The default CI scan uses
> `packages/requirements.txt` and is expected to pass.
> The intentionally vulnerable demo input lives in
> `packages/vulnerable-requirements.txt` and is expected to fail.

---

## Overview

This repository demonstrates an automated vulnerability scanning pipeline
for Python package lists.

The goal is to show how **Software Composition Analysis (SCA)**
can be integrated into a CI/CD workflow to:

- detect vulnerable dependencies on every Pull Request
- classify findings by CVSS severity (CRITICAL / HIGH / MEDIUM / LOW)
- block merges automatically when blocking vulnerabilities are found
- manage accepted risks with an expiry-based ignore list

The original thesis project was implemented in an enterprise GitLab environment.
This public repository contains a simplified, anonymised demo version only.

---

## Architecture

Two security processes are implemented, mirroring the thesis design:

| Process | Trigger | Purpose |
|---------|---------|---------|
| **1. Package Request and Approval** | Pull Request | Security Gate: block merge on findings |
| **2. CVE Lifecycle Management** | Push to main | Post-merge monitoring of the current state |

→ See **[docs/architecture.md](docs/architecture.md)** for full Mermaid diagrams
and a GitLab CI/CD vs GitHub Actions comparison.

```
packages/requirements.txt                 Standard CI input (expected to pass)
packages/vulnerable-requirements.txt      Vulnerability demo input (expected to fail)
        ↓
  scanner/scan.py          Run Trivy, parse JSON output
        ↓
  scanner/main.py          Filter ignored CVEs (ignore-list.yaml)
        ↓
  scanner/classify.py      CVSS-based classification + Security Gate
        ↓
  exit 0 → merge allowed   exit 1 → merge blocked
```

---

## Tech Stack

| Category | Technology |
|----------|-----------|
| SCA / Scanning | [Trivy](https://trivy.dev) |
| CI/CD (this demo) | GitHub Actions |
| CI/CD (original thesis) | GitLab CI/CD |
| Language | Python 3.11 |
| Config | YAML |
| Local tooling | Make |

---

## Key Features

- **Automated vulnerability scanning** via Trivy on every Pull Request
- **CVSS-based classification** into CRITICAL / HIGH / MEDIUM / LOW
- **Security Gate**: exit code 1 blocks the PR merge when MEDIUM or above is found
- **Ignore list** (`scanner/ignore-list.yaml`): temporarily suppress accepted CVEs with expiry dates — re-detected automatically after the deadline
- **CI/CD parity**: `make scan` reproduces the exact same scan that runs in GitHub Actions
- **Separated scan inputs**: clean default CI input and intentionally vulnerable demo input
- **GitLab CI/CD reference** (`docs/.gitlab-ci.yml`): documents the original thesis pipeline design

> **MVP scope:** In this public demo, the ignore list demonstrates the
> accepted-risk lifecycle for selected MEDIUM findings. The policy comments
> require explicit approval for CRITICAL and HIGH findings, but the demo
> does not enforce severity or approval metadata in code. Validating these
> constraints before suppression would be a production hardening step.

---

## Getting Started

### Prerequisites

- Python 3.11+
- [Trivy CLI](https://trivy.dev/latest/getting-started/installation/)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/numa2812/python-package-security-pipeline.git
cd python-package-security-pipeline

# 2. Install Python dependencies
make install

# 3. Install Trivy (Linux / macOS)
make trivy-install
```

### Run the scan

```bash
# Scan default input with ignore list applied (mirrors CI behavior)
make scan

# Run the intentionally vulnerable demo with ignore list applied
make scan-demo

# Run the intentionally vulnerable demo showing all CVEs
make scan-demo-all
```

### Expected output

Running `make scan` against the default `packages/requirements.txt`
is expected to pass:

```
==============================================================
  Python Package Security Pipeline
  Target : packages/requirements.txt
==============================================================

  [Step 1] Loading ignore list for project 'demo-project'...
           2 CVE(s) will be suppressed.

  [Step 2] Running Trivy scan...
           Trivy found 0 vulnerability/vulnerabilities.

  [Step 3] Classifying active vulnerabilities...

  CRITICAL: 0 | HIGH: 0 | MEDIUM: 0 | LOW: 0 | UNKNOWN: 0

  ✅  No active vulnerabilities found.

--------------------------------------------------------------
  ✅  Security Gate PASSED — no MEDIUM/HIGH/CRITICAL found.
--------------------------------------------------------------
```

Running `make scan-demo` against the intentionally vulnerable
`packages/vulnerable-requirements.txt` demonstrates the blocking behavior:

```
==============================================================
  Python Package Security Pipeline
  Target : packages/vulnerable-requirements.txt
==============================================================

  ...

--------------------------------------------------------------
  ❌  Security Gate FAILED — blocking vulnerabilities found.
--------------------------------------------------------------
```

→ See **[docs/example-output.md](docs/example-output.md)** for all three scan scenarios.

---

## Repository Structure

```
python-package-security-pipeline/
├── .github/workflows/
│   └── security-scan.yml     GitHub Actions workflow (active CI/CD)
├── docs/
│   ├── architecture.md       Architecture diagrams (Mermaid)
│   ├── example-output.md     Annotated CLI output examples
│   └── .gitlab-ci.yml        GitLab CI/CD reference (not executable here)
├── packages/
│   ├── requirements.txt                  Default CI input (expected to pass)
│   └── vulnerable-requirements.txt       Demo input (intentionally vulnerable)
├── scanner/
│   ├── scan.py               Trivy invocation and JSON parsing
│   ├── classify.py           CVSS-based classification and Security Gate
│   ├── ignore-list.yaml      Accepted-risk CVE list with expiry dates
│   └── main.py               Pipeline orchestrator (CLI entry point)
└── Makefile                  Local development shortcuts
```

---

## Background

This project is a public, anonymised reimplementation of the prototype
developed for my Bachelor thesis:

> *"Konzeption und Implementierung eines Sicherheitskonzepts
> für eine kontrollierte Bereitstellung von Python-Paketen
> mit dem Posit Package Manager"*
> — DHBW Karlsruhe, B.Sc. Wirtschaftsinformatik, 2026

The thesis designed and implemented two security processes
(Package Request and Approval / CVE Lifecycle Management)
in an enterprise GitLab environment.
This repository demonstrates the same concepts in a portable,
publicly accessible form using GitHub Actions.

---

## Disclaimer

This repository does not contain any confidential company information,
internal infrastructure details, real vulnerability reports,
or production configuration files.

It is a generalised demo project created for portfolio and learning purposes.
All company-specific registry paths, runner configurations,
project names, and credentials have been removed.

---

## Author

**Yuya Kayanuma**

B.Sc. Wirtschaftsinformatik, DHBW Karlsruhe (exp. 09/2026)
Focus: Platform Engineering · DevOps · DevSecOps

[![LinkedIn](https://img.shields.io/badge/LinkedIn-yuya--kayanuma-0077B5?logo=linkedin)](https://linkedin.com/in/yuya-kayanuma-92a699408)
