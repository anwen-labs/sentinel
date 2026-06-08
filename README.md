# Sentinel

**Deterministic Docker Compose security scanner.** Paste or point it at a
`docker-compose.yml` and get a reproducible list of security misconfigurations —
exposed Docker sockets, default credentials, privileged containers, unpinned images,
and more.

- **Deterministic** — same input always produces the same findings and the same
  `report_digest` (a real SHA-256 over the normalized facts + engine/pack versions +
  verdict). No LLM, no flakiness, fully auditable.
- **Private by design** — runs locally, in your CI, or entirely in your browser
  (WASM). Your compose file is never uploaded anywhere.
- **CI-ready** — one exit code gates your pipeline; the same binary runs on your laptop.

## Install

From source (Rust toolchain):

```sh
cargo install --git https://github.com/madrainbo/sentinel sentinel
# or, from a clone:
cargo install --path crates/cli
```

Or download a prebuilt binary for your platform from the
[Releases](https://github.com/madrainbo/sentinel/releases) page (no toolchain needed).

## Usage

```sh
sentinel scan docker-compose.yml                  # human-readable findings
cat docker-compose.yml | sentinel scan -          # read from stdin
sentinel scan docker-compose.yml --format json    # machine-readable report
sentinel scan docker-compose.yml --fail-on high   # exit 1 if any High/Critical (CI gate)
```

## Use in CI (GitHub Actions)

```yaml
- uses: madrainbo/sentinel@v0.1.0
  with:
    path: docker-compose.yml
    fail-on: high      # fail the job on any High/Critical finding
```

The Action downloads a pinned, checksum-verified prebuilt binary for the runner and
runs the **same** `sentinel scan` you run locally — your CI never compiles anything.

## What it checks (v0)

| Rule | Severity | What it catches |
|---|---|---|
| `DOCKER-SOCKET-MOUNT` | Critical | `/var/run/docker.sock` mounted into a container (host root) |
| `PRIVILEGED-CONTAINER` | Critical | `privileged: true` |
| `DANGEROUS-CAPABILITY` | High | `cap_add` of SYS_ADMIN / NET_ADMIN / SYS_PTRACE / … |
| `HOST-NETWORK-MODE` | High | `network_mode: host` |
| `WEAK-DEFAULT-CREDENTIAL` | High | secret-like env var set to a weak/default value |
| `SECRET-IN-ENVIRONMENT` | Medium | secret-like env var with an inline literal value |
| `SENSITIVE-PORT-PUBLISHED-ALL-IFACES` | Medium | datastore/admin port published on `0.0.0.0` |
| `PORT-PUBLISHED-ALL-IFACES` | Low | any port published on all interfaces |
| `IMAGE-UNPINNED` | Low | image not pinned by digest |
| `CONTAINER-RUNS-AS-ROOT-OR-UNKNOWN` | Low | runs as root, or user unspecified |
| `WRITABLE-ROOT-FILESYSTEM` | Low | `read_only` not set |

> Control mappings (CWE / CIS Docker Benchmark) are shipped as guidance and are being
> verified against the published benchmarks.

## How it works

```
docker-compose.yml  →  parser  →  fact model (entity/relation graph)
                                      → rules engine → findings
                                      → content-addressed report (SHA-256)
```

The parser normalizes Compose into a technology-agnostic fact graph; rules are pure
predicates over that graph; the report is hashed so it can be reproduced and verified.

## Build & test

```sh
cargo build --release
cargo test --workspace
cargo run -p harness        # eval harness: precision/recall over a labeled corpus
```

## Web demo

```sh
cargo install wasm-pack
wasm-pack build crates/web --target web --out-dir site/pkg --release
python -m http.server 8849 --directory crates/web/site   # http://localhost:8849
```

## License

MIT — see [LICENSE](LICENSE).
