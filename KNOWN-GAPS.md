# Known gaps

Sentinel does one layer — configuration misconfiguration — and we'd rather name what it
*doesn't* catch than imply it catches everything. This is the companion to
[BENCHMARK.md](BENCHMARK.md): the held-out benchmark measures accuracy on inputs the engine
was never tuned on; this file lists the limitations we know about. Found one that isn't here?
Open an issue — published misses are the point.

## Coverage gaps (in scope, not yet fully caught)

- **Kubernetes reachability for Deployment-backed selectorless Services.** The cross-resource
  `K8S-REACHABLE-NODE-COMPROMISE` chain resolves an Ingress / Gateway / Endpoints → Service →
  Workload path. Selectorless Services wired by manual `Endpoints` / `EndpointSlice` are now
  modeled — but only to **bare Pods** (a `targetRef` pod name that matches a `Pod`). When the
  endpoints target Deployment-managed pods (generated pod names), the Service still isn't
  chained to the workload, because pod → owner resolution isn't modeled. The per-workload
  findings (privileged, hostPath, dangerous capability, …) still fire regardless.

## Scope limits (by design — pair with other tools)

- **Helm / templated YAML isn't rendered.** Files with `{{ … }}` templating are detected and
  skipped rather than guessed at. Run Sentinel on rendered manifests (`helm template`).
- **The browser demo scans one file at a time.** The CLI scans whole directories/repos.
- **Configuration only.** Not CVEs/dependencies (Trivy, Dependabot), not source-code SAST
  (CodeQL, Semgrep), not secrets in git *history* (gitleaks, trufflehog — Sentinel scans the
  file you give it, not commits), not runtime (Falco). See the "Scope" section on the site.

## Recently closed

Earlier editions of this file also listed the modern `/run/docker.sock` path, the standalone
`aws_vpc_security_group_ingress_rule`, the `postgres` weak-default, the `AKIA…EXAMPLE` comment
false positive, non-canonical IPv6 `::/0` spellings (standalone **and** inline security-group
rules), Gateway-API (`HTTPRoute`) reachability, and docs-example tokens in `;` / `--` / `/* */`
comments. Those are now caught — see the git history and [BENCHMARK.md](BENCHMARK.md).

## Measurement caveat

On the held-out set, the one raw false positive is a `K8S-CONTAINER-RUNS-AS-ROOT` finding on a
privileged pod that sets no `runAsNonRoot` — i.e. a **correct** detection the external fixture
under-labeled, not an engine error (adjudicated precision 1.00). Details in
[BENCHMARK.md](BENCHMARK.md).
