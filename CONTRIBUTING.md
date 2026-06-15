# Contributing to Sentinel

Thanks for helping. Sentinel's promise is **provable, not promised** — so the bar
for a change is evidence, not assertion: it builds, the eval harness still passes,
and behavior is demonstrated against real input.

## Prerequisites

- A recent Rust toolchain (`rustup`); the workspace builds offline. `Cargo.lock` is
  lockfile v4 and the dependency tree needs a current stable rustc.
- That's it — the engine has no runtime dependencies and makes no network calls.

## Build, test, scan

```sh
cargo build --release            # binary: target/release/sentinel
cargo test --workspace           # unit tests
cargo run -p harness             # the eval harness (the CI gate) — see below
cargo run -p cli -- rules        # print the rule catalog (source of truth for RULES.md)
./target/release/sentinel scan examples/insecure-compose.yml
```

## The eval harness is the gate

`crates/harness` runs the engine over a labeled corpus (`crates/harness/corpus/`)
and **gates CI**: precision/recall, zero missed Critical/High findings, and
per-fixture determinism must all hold. A held-out set lives in
`crates/harness/corpus-holdout/` — run it without clobbering the in-repo one:

```sh
cargo run -p harness                                  # in-repo corpus (the gate)
cargo run -p harness -- crates/harness/corpus-holdout # held-out benchmark
```

Fixtures are labeled with header comments — `# EXPECT: <Severity> <RULE-ID>` for a
finding the engine must produce (matched on **both** rule id and severity), and
`# EXPECT-GAP:` for a known, surfaced-not-failed limitation. A fixture with no
`EXPECT` lines is a clean case (expect zero findings). **Add a fixture for every
behavior change** — a regression you can't reproduce in the corpus isn't fixed.

## Adding or changing a rule

Sentinel is **pure predicates over a fact graph** — keep parsing in the parser and
detection in the rule:

1. The parser (`crates/*-parser`) emits the fact (an entity attribute or relation).
2. The rule (`crates/pack-*`) is a pure function reading that fact. Register it in
   the pack's rule list and add a `RuleMeta` entry to its `catalog()`.
3. `RULES.md` is **generated** — regenerate and commit it; CI checks for drift:
   ```sh
   cargo run -p cli -- rules > RULES.md
   ```
4. Add corpus fixture(s) proving the new behavior, and run the harness.

## Invariants — do not break

- **Determinism.** Same input → same `report_digest`. Sort before emitting ordered
  output; never let output order depend on HashMap/HashSet iteration. The harness
  checks this per fixture.
- **Versioned digest.** `report_digest` = SHA-256 over the normalized facts +
  `pack_version_hash` + verdict. Don't alter the digest computation path —
  `verify`/reproducibility is the core promise. Bump the version when detection
  behavior changes.
- **No network, no telemetry in the engine.** Configs never leave the machine.

## Commits & PRs

- **Conventional commits** (`fix:`, `feat:`, `docs:`, `test:`, `chore:` …) with a
  scope where it helps (`fix(k8s): …`).
- Before opening a PR: `cargo test --workspace`, `cargo run -p harness` (gate
  green), and regenerate `RULES.md` if any rule metadata changed.
- In the PR, show the evidence: the harness summary and, for behavior changes, the
  before/after on a concrete input.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md), not a
public issue.
