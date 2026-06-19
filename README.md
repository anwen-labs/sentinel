# Sentinel

**Deterministic security scanner for your infrastructure configs.** Point it at a
Docker Compose file, Dockerfile, Kubernetes manifest, GitHub Actions workflow,
Terraform file, or `.env`/config — and get a reproducible list of security
misconfigurations: exposed Docker sockets, default credentials, privileged
containers, cluster-admin bindings, pwn-request workflows, open security groups,
hardcoded keys, and more.

> ### 🚀 [Try the live demo →](https://sentinel-engine-ggaj.onrender.com/)
> Paste any supported config and scan it **entirely in your browser**
> (WebAssembly — nothing is uploaded). Same engine as this CLI.

- **Deterministic** — same input always produces the same findings and the same
  `report_digest` (a real SHA-256 over the normalized facts + engine/pack versions +
  verdict). No LLM, no flakiness, fully auditable.
- **Private by design** — runs locally and in your CI. Your config is never
  uploaded anywhere; the tool makes no network calls.
- **CI-ready** — one exit code gates your pipeline; the same binary runs on your laptop.

> ⚠️ **Early release — actively developed.** APIs and rule sets may still change
> between versions; findings format is stable within a minor series.

## What it scans

| Target | Rules | Highlights |
|---|---|---|
| **Docker Compose** | 23 | Docker-socket mounts, privileged containers, weak/default credentials, host namespaces, attack-path chains |
| **Kubernetes** | 19 | privileged/hostPath, cluster-admin & wildcard RBAC, seccomp unconfined, reachable node-compromise chains |
| **Dockerfile** | 8 | `curl \| sh`, disabled TLS verification, root user, build secrets, unpinned base images |
| **Secrets / config** | 8 | AWS/GitHub/Stripe/Slack/SendGrid/Google keys, private keys, generic credentials |
| **GitHub Actions** | 6 | pwn-request, script injection, write-all permissions, unpinned actions |
| **Terraform** | 6 | open security groups, public S3 ACLs, IAM wildcards, plaintext secrets, unencrypted storage |

**70 rules total** (64 default + 6 opt-in `--strict` hardening checks). Full
per-rule reference — what each finds, why it matters, how to fix it — in
**[RULES.md](RULES.md)** (generated from the engine itself; findings and SARIF
deep-link into it). Control mappings (CWE, CIS, MITRE ATT&CK): **[CONTROLS.md](CONTROLS.md)**.

## Scope — one layer, not your whole security program

Security is layered. Sentinel does **configuration misconfiguration** deterministically
and with high precision — we'd rather be precise about a slice than vague about
everything, and we publish a held-out accuracy benchmark with the misses included
([BENCHMARK.md](BENCHMARK.md)). Pair it with the tools below for defense in depth.

**Sentinel catches:** misconfigurations across the six formats above (70 rules) —
container escape, exposed services, default/leaked credentials, over-broad permissions,
supply-chain gaps — with source-line references, CWE / CIS / MITRE ATT&CK mappings, and a reproducible
digest.

**Sentinel does _not_ (use it alongside):**

- Vulnerable **dependencies** / CVEs → Dependabot, Trivy, `cargo audit`
- Source-code vulnerabilities (**SAST**) → CodeQL, Semgrep
- Secrets in **git history** — it scans the file you give it, not your commits → gitleaks, trufflehog
- **Runtime** threats → Falco, your EDR
- Helm / Kustomize **templates** aren't *rendered* — they're detected and skipped, so render first (`helm template`) then scan

## Install

**Prebuilt binary** (no toolchain needed) — download the archive for your platform
from [Releases](https://github.com/anwen-labs/sentinel/releases/latest)
(Linux x86_64/aarch64 · macOS x86_64/aarch64 · Windows x86_64), check the
`.sha256`, and put `sentinel` on your `PATH`:

```sh
curl -fsSLO https://github.com/anwen-labs/sentinel/releases/download/v0.1.6/sentinel-v0.1.6-x86_64-unknown-linux-gnu.tar.gz
curl -fsSLO https://github.com/anwen-labs/sentinel/releases/download/v0.1.6/sentinel-v0.1.6-x86_64-unknown-linux-gnu.sha256
sha256sum -c <(awk '{print $1"  sentinel-v0.1.6-x86_64-unknown-linux-gnu.tar.gz"}' sentinel-v0.1.6-x86_64-unknown-linux-gnu.sha256)
tar xzf sentinel-v0.1.6-x86_64-unknown-linux-gnu.tar.gz && sudo mv sentinel /usr/local/bin/
```

**From source** (requires the [Rust toolchain](https://rustup.rs) and Git):

```sh
cargo install --git https://github.com/anwen-labs/sentinel sentinel
# or, from a clone:
cargo install --path crates/cli
```

## Usage

```sh
sentinel scan docker-compose.yml                  # type auto-detected
sentinel scan Dockerfile
sentinel scan deployment.yaml                     # Kubernetes (multi-doc aware)
sentinel scan .github/workflows/ci.yml            # GitHub Actions
sentinel scan main.tf                             # Terraform (HCL)
sentinel scan .env                                # secrets sweep
cat docker-compose.yml | sentinel scan -          # read from stdin
sentinel scan compose.yml --format json           # machine-readable report
sentinel scan compose.yml --format sarif          # SARIF for GitHub code scanning
sentinel scan compose.yml --fail-on high          # exit 1 on High/Critical (CI gate)
sentinel scan compose.yml --strict                # + best-practice hardening checks
sentinel verify report.json compose.yml           # re-check a saved report reproduces
sentinel rules                                    # the full rule catalog as Markdown
```

**SARIF** output drops findings straight into the GitHub Security tab:

```yaml
- run: sentinel scan docker-compose.yml --format sarif > sentinel.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel.sarif
```

**`verify`** re-runs the scan and checks the result reproduces the report's
`report_digest` — the content-addressing guarantee, usable by an auditor.

## Use in CI (GitHub Actions)

One line gates your pipeline:

```yaml
- uses: anwen-labs/sentinel@v0.1.6
  with:
    path: docker-compose.yml
    fail-on: high      # fail the job on any High/Critical finding
```

The Action downloads a pinned, checksum-verified prebuilt binary for the runner and
runs the **same** `sentinel scan` you run locally — your CI never compiles anything.

## Use with Claude Code (agent skill)

This repo is also a Claude Code plugin marketplace. Installing it teaches the agent
to scan IaC files with Sentinel, fix findings by source line, re-scan until
`CLEARED`, and verify the report digest — deterministic verdicts instead of
model judgment:

```
/plugin marketplace add anwen-labs/sentinel
/plugin install sentinel-scanner@sentinel
```

The skill lives in [`skills/scan-iac-with-sentinel/`](skills/scan-iac-with-sentinel/SKILL.md)
and works with any [agentskills.io](https://agentskills.io)-compatible agent.

## How it works

```
config file  →  parser  →  fact model (entity/relation graph)
                               → rules engine → findings (with source lines)
                               → content-addressed report (SHA-256)
```

Each parser normalizes its format into a technology-agnostic fact graph; rules are
pure predicates over that graph; the report is hashed so it can be reproduced and
verified. Findings carry the source line(s) they came from.

## Build & test

```sh
cargo build --release
cargo test --workspace
cargo run -p harness        # eval harness: precision/recall over a labeled corpus
```

The harness runs the engine over a labeled corpus across all six formats and gates CI
on precision/recall 1.000 on that corpus plus per-fixture determinism. Accuracy on a
separate **held-out** set the engine was never tuned on — misses included — is reported
in [BENCHMARK.md](BENCHMARK.md), with documented limitations in [KNOWN-GAPS.md](KNOWN-GAPS.md).

## License

MIT — see [LICENSE](LICENSE).
