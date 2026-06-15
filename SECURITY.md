# Security policy

Sentinel is a security tool, so we hold its own code to the standard it checks for.
The engine is deterministic and **makes no network calls** — your configs never
leave your machine (CLI) or your browser (the WASM demo). Its attack surface is the
**parsers**, which by design ingest untrusted input.

## Supported versions

Sentinel is pre‑1.0; only the latest published version receives security fixes.

| Version | Supported |
|---|---|
| latest `0.1.x` | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security problems.** Use GitHub's private
reporting:

1. Go to the repository's **Security** tab → **Report a vulnerability** (GitHub
   Private Vulnerability Reporting), or
2. Open a [draft security advisory](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

Please include: affected version, a minimal input/config that reproduces it, the
observed vs. expected behavior, and impact. We aim to acknowledge within **3
business days** and to ship a fix or mitigation for confirmed issues before any
public disclosure. We'll credit reporters who want it.

### In scope
- Parser crashes, panics, or resource exhaustion on crafted input (DoS).
- A way to make the engine **miss** a finding it documents (a security
  false‑negative) or **fabricate** one (false positive) — see
  [BENCHMARK.md](BENCHMARK.md) and [KNOWN-GAPS.md](KNOWN-GAPS.md) for what's already
  known.
- Breaking the determinism / `report_digest` reproducibility guarantee.

### Out of scope
- The documented [known gaps](KNOWN-GAPS.md) and by‑design scope limits.
- Findings about *your* config (that's what the tool is for — run it).

## Our own bar

Per the project's engineering rules, nothing is called "production‑ready" until it
passes a dedicated security review of the parsers/inputs (`/security-review`) — that
gate is tracked and pending. Input‑safety hardening (oversized input, YAML
alias‑bombs, recursion/stack‑overflow guards) is in place. The dependency tree is gated
by [`deny.toml`](deny.toml) (cargo‑deny) in CI.
