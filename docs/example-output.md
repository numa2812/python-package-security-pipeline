# Example Output

This document shows abbreviated sample output from the scanner pipeline
running against `packages/vulnerable-requirements.txt`.

The exact number of findings can change as Trivy's vulnerability database evolves.
The package versions shown here correspond to the intentionally vulnerable packages
defined in `packages/vulnerable-requirements.txt`.
No real infrastructure or production data is involved.

---

## Case 1: Without ignore list

Representative detected CVEs are shown. The Security Gate fails because
CRITICAL and HIGH vulnerabilities are present.

```
$ python -m scanner.main packages/vulnerable-requirements.txt

==============================================================
  Python Package Security Pipeline
  Target : packages/vulnerable-requirements.txt
==============================================================

  [Step 1] Ignore list disabled.

  [Step 2] Running Trivy scan...
           Trivy found 54 vulnerability/vulnerabilities.

  [Step 3] Classifying active vulnerabilities...

  CRITICAL: 2 | HIGH: 1 | MEDIUM: 2 | LOW: 0

  🔴  CVE-2020-1747 : PyYAML 5.1 → 5.3.1        (CVSS 9.8)
  🔴  CVE-2021-25289: Pillow 8.1.0 → 8.2.0       (CVSS 9.8)
  🟠  CVE-2019-10906: Jinja2 2.10.1 → 2.11.3     (CVSS 8.1)
  🟡  CVE-2019-11236: urllib3 1.24.1 → 1.24.2    (CVSS 6.5)
  🟡  CVE-2018-18074: requests 2.18.0 → 2.20.0   (CVSS 5.0)
  ...

--------------------------------------------------------------
  ❌  Security Gate FAILED — blocking vulnerabilities found.
--------------------------------------------------------------
```

**Exit code:** `1` → the Security Gate fails intentionally for the demo input.

---

## Case 2: With ignore list (`--ignore-list`)

Two MEDIUM CVEs are suppressed by `scanner/ignore-list.yaml`
because they are registered as accepted risk with a future expiry date.
The Security Gate still fails because CRITICAL and HIGH remain.

```
$ python -m scanner.main packages/vulnerable-requirements.txt --ignore-list

==============================================================
  Python Package Security Pipeline
  Target : packages/vulnerable-requirements.txt
==============================================================

  [Step 1] Loading ignore list for project 'demo-project'...
           2 CVE(s) will be suppressed.

  [Step 2] Running Trivy scan...
           Trivy found 54 vulnerability/vulnerabilities.

  Ignored CVEs (2 suppressed by ignore list):
  ⏭   CVE-2018-18074: requests 2.18.0
  ⏭   CVE-2019-11236: urllib3 1.24.1

  [Step 3] Classifying active vulnerabilities...

  CRITICAL: 2 | HIGH: 1 | MEDIUM: 0 | LOW: 0

  🔴  CVE-2020-1747 : PyYAML 5.1 → 5.3.1        (CVSS 9.8)
  🔴  CVE-2021-25289: Pillow 8.1.0 → 8.2.0       (CVSS 9.8)
  🟠  CVE-2019-10906: Jinja2 2.10.1 → 2.11.3     (CVSS 8.1)
  ...

--------------------------------------------------------------
  ❌  Security Gate FAILED — blocking vulnerabilities found.
--------------------------------------------------------------
```

**Exit code:** `1` → the Security Gate fails intentionally for the demo input.

> **MVP scope:** In this public demo, the ignore list demonstrates the
> accepted-risk lifecycle for selected MEDIUM findings. The policy comments
> require explicit approval for CRITICAL and HIGH findings, but the demo
> does not enforce severity or approval metadata in code. Validating these
> constraints before suppression would be a production hardening step.

---

## Case 3: Expired ignore list entry (automatic re-detection)

When the `expires` date of an entry in `ignore-list.yaml` has passed,
the CVE is automatically re-detected — no code change is needed.

```
$ python -m scanner.main packages/vulnerable-requirements.txt --ignore-list

  [Step 1] Loading ignore list for project 'demo-project'...
  ⏰  CVE-2018-18074: ignore period expired (2026-12-31) — re-detecting
           1 CVE(s) will be suppressed.
  ...
  🟡  CVE-2018-18074: requests 2.18.0 → 2.20.0   (CVSS 5.0)  ← re-appeared
```

This mechanism ensures that accepted risks are revisited before their deadline,
corresponding to the CVE lifecycle management process in the thesis (section 4.3.2).

---

## CVE reference

| CVE ID | Package | Installed | Fixed | Severity | CVSS |
|--------|---------|-----------|-------|----------|------|
| CVE-2020-1747 | PyYAML | 5.1 | 5.3.1 | CRITICAL | 9.8 |
| CVE-2021-25289 | Pillow | 8.1.0 | 8.2.0 | CRITICAL | 9.8 |
| CVE-2019-10906 | Jinja2 | 2.10.1 | 2.11.3 | HIGH | 8.1 |
| CVE-2019-11236 | urllib3 | 1.24.1 | 1.24.2 | MEDIUM | 6.5 |
| CVE-2018-18074 | requests | 2.18.0 | 2.20.0 | MEDIUM | 5.0 |

This table is representative rather than exhaustive. Newer Trivy databases may
report additional CVEs for the same intentionally outdated package versions.
