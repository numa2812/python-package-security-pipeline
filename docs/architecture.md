# Architecture

This document describes the pipeline design of the Python Package Security Pipeline,
covering both Process 1 (MR-triggered Security Gate) and
Process 2 (scheduled CVE lifecycle scan).

Both processes are based on the security concept designed in the Bachelor thesis,
implemented originally in GitLab CI/CD and ported to GitHub Actions for this public demo.

---

## Components

| File | Role |
|------|------|
| `packages/requirements.txt` | Input: Python dependency list to be scanned |
| `scanner/scan.py` | Runs Trivy via subprocess; parses JSON output |
| `scanner/classify.py` | Groups CVEs by CVSS severity; evaluates Security Gate |
| `scanner/ignore-list.yaml` | Configuration: CVEs accepted as known risk (with expiry) |
| `scanner/main.py` | Orchestrator: coordinates scan → filter → classify → report |
| `.github/workflows/security-scan.yml` | CI/CD automation (GitHub Actions) |
| `.gitlab-ci.yml` | Reference: original GitLab CI/CD design (not executable here) |

---

## Process 1: Package Request and Approval (MR-triggered)

Triggered automatically when a Pull Request modifies `packages/requirements.txt`
or any file under `scanner/`.
The pipeline acts as a **Security Gate**: the merge is blocked if any
MEDIUM, HIGH, or CRITICAL vulnerability is found in the active CVE list.

```mermaid
flowchart TD
    subgraph trigger["🔀 Trigger: Pull Request"]
        PR[/"Pull Request\n(packages/ changed)"/]
    end

    subgraph ci["⚙️ CI/CD  (GitHub Actions / GitLab CI)"]
        GH["security-scan.yml\n.gitlab-ci.yml"]
    end

    subgraph pipeline["🐍 Scanner Pipeline"]
        direction TB
        REQ[/"packages/\nrequirements.txt"/]
        SCAN["scan.py\nRun Trivy via subprocess"]
        IGN[/"scanner/\nignore-list.yaml"/]
        FILTER["main.py\nFilter ignored CVEs"]
        CLASSIFY["classify.py\nCVSS-based classification"]
    end

    subgraph gate["🔒 Security Gate"]
        direction LR
        PASS(["✅ exit 0\nMerge allowed"])
        FAIL(["❌ exit 1\nMerge blocked"])
    end

    PR --> GH
    GH --> REQ
    REQ --> SCAN
    SCAN -->|"Vulnerability list\n(JSON)"| FILTER
    IGN -->|"Ignored CVE IDs"| FILTER
    FILTER -->|"Active CVEs only"| CLASSIFY
    CLASSIFY -->|"CRITICAL / HIGH / MEDIUM"| FAIL
    CLASSIFY -->|"LOW only / clean"| PASS

    classDef triggerStyle fill:#4a4a6a,stroke:#8888cc,color:#fff
    classDef ciStyle fill:#2d4a2d,stroke:#55aa55,color:#fff
    classDef fileStyle fill:#3a3a3a,stroke:#888,color:#ddd
    classDef processStyle fill:#1a3a5a,stroke:#4488cc,color:#fff
    classDef passStyle fill:#1a5a1a,stroke:#55aa55,color:#fff
    classDef failStyle fill:#5a1a1a,stroke:#cc4444,color:#fff

    class PR triggerStyle
    class GH ciStyle
    class REQ,IGN fileStyle
    class SCAN,FILTER,CLASSIFY processStyle
    class PASS passStyle
    class FAIL failStyle
```

### Security Gate threshold

| Severity | CVSS Score | Gate result |
|----------|-----------|-------------|
| CRITICAL | ≥ 9.0 | ❌ Blocked |
| HIGH | 7.0 – 8.9 | ❌ Blocked |
| MEDIUM | 4.0 – 6.9 | ❌ Blocked |
| LOW | 0.1 – 3.9 | ✅ Allowed |
| None | — | ✅ Allowed |

---

## Process 2: CVE Lifecycle Management (scheduled)

Triggered on every push to `main` and optionally on a daily schedule.
Monitors the **current state** of all packages after each merge.
Expired entries in `ignore-list.yaml` are automatically re-detected,
ensuring that accepted risks are revisited before their deadline.

```mermaid
flowchart TD
    subgraph trigger2["⏰ Trigger: Push to main / Scheduled"]
        SCHED[/"Push to main\nor daily schedule"/]
    end

    subgraph pipeline2["🐍 Scanner Pipeline"]
        direction TB
        REQ2[/"packages/\nrequirements.txt"/]
        SCAN2["scan.py\nRun Trivy"]
        IGN2[/"ignore-list.yaml\n(expired entries re-detected)"/]
        FILTER2["main.py\nFilter and Classify"]
    end

    subgraph result["📊 Result"]
        direction LR
        CLEAN(["✅ exit 0\nAll clear"])
        VULN(["⚠️ exit 1\nNew CVEs detected\nLogged in CI output"])
    end

    SCHED --> REQ2
    REQ2 --> SCAN2
    SCAN2 --> FILTER2
    IGN2 --> FILTER2
    FILTER2 -->|"Clean"| CLEAN
    FILTER2 -->|"CRITICAL / HIGH / MEDIUM"| VULN

    classDef triggerStyle fill:#4a4a6a,stroke:#8888cc,color:#fff
    classDef fileStyle fill:#3a3a3a,stroke:#888,color:#ddd
    classDef processStyle fill:#1a3a5a,stroke:#4488cc,color:#fff
    classDef cleanStyle fill:#1a5a1a,stroke:#55aa55,color:#fff
    classDef vulnStyle fill:#5a3a1a,stroke:#cc8844,color:#fff

    class SCHED triggerStyle
    class REQ2,IGN2 fileStyle
    class SCAN2,FILTER2 processStyle
    class CLEAN cleanStyle
    class VULN vulnStyle
```

---

## Module dependency

```mermaid
flowchart LR
    MAIN["scanner/main.py\n(orchestrator)"]
    SCAN["scanner/scan.py"]
    CLASSIFY["scanner/classify.py"]
    IGN[/"scanner/ignore-list.yaml"/]
    REQ[/"packages/requirements.txt"/]
    TRIVY(["Trivy CLI"])

    MAIN -->|"calls"| SCAN
    MAIN -->|"calls"| CLASSIFY
    MAIN -->|"reads"| IGN
    SCAN -->|"subprocess"| TRIVY
    TRIVY -->|"scans"| REQ
    SCAN -->|"returns vuln list"| MAIN
    CLASSIFY -->|"returns classified dict"| MAIN

    classDef moduleStyle fill:#1a3a5a,stroke:#4488cc,color:#fff
    classDef fileStyle fill:#3a3a3a,stroke:#888,color:#ddd
    classDef toolStyle fill:#2d4a2d,stroke:#55aa55,color:#fff

    class MAIN,SCAN,CLASSIFY moduleStyle
    class IGN,REQ fileStyle
    class TRIVY toolStyle
```

---

## GitLab CI/CD vs GitHub Actions

The same pipeline logic is expressed in both CI/CD systems.

```mermaid
flowchart LR
    subgraph gitlab["GitLab CI/CD  (original thesis)"]
        GL_TRIGGER["rules:\n merge_request_event"]
        GL_JOB["trivy_scan_on_merge_request"]
        GL_SCRIPT["script:\n python -m scanner.main"]
    end

    subgraph github["GitHub Actions  (this demo)"]
        GH_TRIGGER["on:\n pull_request"]
        GH_JOB["security-scan"]
        GH_SCRIPT["run:\n python -m scanner.main"]
    end

    GL_TRIGGER -.->|"equivalent"| GH_TRIGGER
    GL_JOB     -.->|"equivalent"| GH_JOB
    GL_SCRIPT  -.->|"identical"| GH_SCRIPT

    classDef gitlabStyle fill:#4a2d6a,stroke:#9966cc,color:#fff
    classDef githubStyle fill:#2d4a2d,stroke:#55aa55,color:#fff

    class GL_TRIGGER,GL_JOB,GL_SCRIPT gitlabStyle
    class GH_TRIGGER,GH_JOB,GH_SCRIPT githubStyle
```
