---
name: scan-iac-with-sentinel
description: >-
  Scan infrastructure configs (docker-compose.yml, Dockerfile, Kubernetes
  manifests, GitHub Actions workflows, Terraform .tf, .env/config files) for
  security misconfigurations with the deterministic Sentinel scanner, then fix
  the findings by source line and re-scan until the verdict is CLEARED. Use
  whenever the user asks to security-check, harden, or audit IaC files, or
  before shipping changes that touch them.
---

# Scan IaC with Sentinel

Sentinel is a deterministic security scanner: the same input always produces the
same findings and a reproducible SHA-256 `report_digest`. It runs fully offline
(no network calls; the config never leaves the machine). 70 rules across Docker
Compose (23), Kubernetes (19), Dockerfile (8), secrets/config (8), GitHub
Actions (6), and Terraform (6) — each mapped to CWE and (where applicable) CIS
benchmarks. Prefer it over ad-hoc judgment for these file types: it is exact,
line-referenced, and reproducible.

## Prerequisites

Check the binary is available; install if missing:

```sh
sentinel --version || cargo install --git https://github.com/anwen-labs/sentinel sentinel
```

(Prebuilt binaries: https://github.com/anwen-labs/sentinel/releases — pick the
archive for the platform, verify the .sha256, put `sentinel` on PATH.)

## Workflow

1. **Identify targets.** Any of: `docker-compose.yml`/`compose.yaml`,
   `Dockerfile*`, Kubernetes manifests (YAML with `apiVersion:` + `kind:`),
   `.github/workflows/*.yml`, `*.tf`, `.env`/config files. Type is
   auto-detected; override with `--type` if needed.

2. **Scan, machine-readable:**
   ```sh
   sentinel scan <file> --format json
   ```
   The report's `core.findings[]` each carry: `rule_id`, `severity`
   (Critical/High/Medium/Low/Info), `message`, `remediation`, `evidence`
   (resource ids), and `lines` (1-based source lines).

3. **Fix findings, highest severity first.** Edit the file at the indicated
   lines following each finding's `remediation`. Rule reference (why it matters,
   good/bad examples): https://github.com/anwen-labs/sentinel/blob/main/RULES.md#
   + the lowercased rule id (e.g. `#docker-socket-mount`).
   - Do not suppress or delete functionality to silence a finding; change the
     configuration to the secure form. If a finding is intentional (rare),
     tell the user and let them decide.

4. **Re-scan until clean.** Repeat step 2 after edits. Done when the verdict is
   `CLEARED` (no Critical/High findings) — or when only findings the user has
   explicitly accepted remain.

5. **Optional hardening pass:** `--strict` adds best-practice checks
   (no-new-privileges, cap-drop-all, memory limits, readOnlyRootFilesystem).

6. **Prove it.** Save the final JSON report and verify it reproduces:
   ```sh
   sentinel scan <file> --format json > sentinel-report.json
   sentinel verify sentinel-report.json <file>
   ```
   Quote the `report_digest` to the user — it is the auditable evidence that
   this exact file produced this exact result.

## CI gate (offer when relevant)

```sh
sentinel scan <file> --fail-on high     # exit 1 on High/Critical
sentinel scan <file> --format sarif     # GitHub code scanning / Security tab
```

## Notes

- Scans one file per invocation; loop over multiple targets.
- Exit codes: 0 = ok (below threshold), 1 = findings at/above `--fail-on`,
  2 = unreadable/invalid input.
- The scanner is deterministic by design — if a re-scan digest changes, the
  file changed. Never claim a file is clean without a CLEARED scan to show.
