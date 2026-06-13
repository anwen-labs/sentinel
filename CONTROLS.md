# Control mappings

Every Sentinel finding cites the standards it maps to. This table documents those
mappings and their basis.

- **CWE** titles are from the public [MITRE CWE](https://cwe.mitre.org/) list (CWE 4.x).
- **CIS** references are section numbers from the **CIS Docker Benchmark** (Section 4 =
  Container Images, Section 5 = Container Runtime). The benchmark itself is published by
  the Center for Internet Security under their own license; the section numbers below are
  the stable identifiers used across recent v1.x releases. Confirm against the licensed
  copy for your target version. Mappings without a CIS entry are best captured by CWE
  alone.

| Rule | Severity | CWE | CIS Docker Benchmark |
|---|---|---|---|
| `DOCKER-SOCKET-MOUNT` | Critical | CWE-250 Execution with Unnecessary Privileges | 5.31 Docker socket not mounted in containers |
| `SENSITIVE-HOST-PATH-MOUNT` | Critical/High | CWE-552 Files/Dirs Accessible to External Parties; CWE-668 Exposure to Wrong Sphere | — |
| `PRIVILEGED-CONTAINER` | Critical | CWE-250 | 5.4 Privileged containers not used |
| `DANGEROUS-CAPABILITY` | High | CWE-250 | 5.3 Linux kernel capabilities restricted |
| `HOST-NETWORK-MODE` | High | CWE-668 | 5.9 Host network namespace not shared |
| `HOST-PID-NAMESPACE` | High | CWE-668 | 5.15 Host process namespace not shared |
| `HOST-IPC-NAMESPACE` | High | CWE-668 | 5.16 Host IPC namespace not shared |
| `WEAK-DEFAULT-CREDENTIAL` | High | CWE-798 Use of Hard-coded Credentials; CWE-1392 Use of Default Credentials | — |
| `SECRET-IN-ENVIRONMENT` | Medium | CWE-256 Plaintext Storage of a Password; CWE-798 | — |
| `SENSITIVE-PORT-PUBLISHED-ALL-IFACES` | Medium | CWE-668 | — |
| `PORT-PUBLISHED-ALL-IFACES` | Low | CWE-668 | — |
| `IMAGE-UNPINNED` | Low | CWE-494 Download of Code Without Integrity Check; CWE-1357 Reliance on Insufficiently Trustworthy Component | — |
| `CONTAINER-RUNS-AS-ROOT-OR-UNKNOWN` | Low | CWE-250 | 4.1 Run containers as a non-root user |
| `WRITABLE-ROOT-FILESYSTEM` | Low | CWE-732 Incorrect Permission Assignment for Critical Resource | 5.12 Root filesystem mounted read-only |

## CIS Kubernetes Benchmark (k8s pack)

CIS references for the Kubernetes pack are section numbers from the **CIS Kubernetes
Benchmark v1.10**, Section 5 (Policies). Numbers were verified against the
[kube-bench](https://github.com/aquasecurity/kube-bench) `cis-1.10` config — the
canonical open implementation. (Section 5.2 numbering shifted between benchmark
versions; an earlier draft used the v1.6/1.7 numbers, which were off by one for most
5.2.x checks — now corrected to v1.10.)

| Rule | CIS Kubernetes v1.10 |
|---|---|
| `K8S-CLUSTER-ADMIN-BINDING` | 5.1.1 cluster-admin role only used where required |
| `K8S-RBAC-SECRET-READ` | 5.1.2 Minimize access to secrets |
| `K8S-RBAC-WILDCARD` | 5.1.3 Minimize wildcard use in Roles/ClusterRoles |
| `K8S-AUTOMOUNT-SA-TOKEN` | 5.1.6 SA tokens only mounted where necessary |
| `K8S-PRIVILEGED-CONTAINER` | 5.2.2 Minimize admission of privileged containers |
| `K8S-HOST-PID` | 5.2.3 host process ID namespace |
| `K8S-HOST-IPC` | 5.2.4 host IPC namespace |
| `K8S-HOST-NETWORK` | 5.2.5 host network namespace |
| `K8S-ALLOW-PRIVILEGE-ESCALATION` | 5.2.6 allowPrivilegeEscalation |
| `K8S-CONTAINER-RUNS-AS-ROOT` | 5.2.7 root containers |
| `K8S-CAP-ADD-ALL`, `K8S-DANGEROUS-CAPABILITY` | 5.2.9 added capabilities |
| `K8S-HOSTPATH-MOUNT` | 5.2.12 HostPath volumes |
| `K8S-SECCOMP-UNCONFINED` | 5.7.2 seccomp profile set to RuntimeDefault |

Other K8s rules (`K8S-PRIVILEGED-*` reachability, `K8S-IMAGE-UNPINNED`,
`K8S-SECRET-IN-MANIFEST`, `K8S-READONLY-ROOTFS-MISSING`, `K8S-ALLOW-PRIV-ESC-NOT-DISABLED`)
are captured by CWE alone.

## CWE-only packs (GitHub Actions, Terraform, secrets)

These packs map to **CWE only** — no single CIS benchmark cleanly covers GitHub Actions
workflow risks, Terraform/IaC misconfigurations, or leaked-credential detection, so a CWE
mapping is the honest, framework-neutral classification. The full per-rule CWE list is in
[RULES.md](RULES.md), which is generated from the engine's own catalog.

## MITRE ATT&CK technique mappings

Each rule that maps to an adversary behaviour carries a `ATTACK-T####` control (in
findings, SARIF, the report, and [RULES.md](RULES.md)) alongside its CWE/CIS mappings.
Techniques are from **MITRE ATT&CK Enterprise** (the Containers matrix techniques were
confirmed live against attack.mitre.org). 62 of 70 rules are mapped; the 8 pure-hardening
rules (non-root user, read-only rootfs, cap-drop-all, sudo-in-build, encryption-at-rest)
are deliberately left unmapped rather than forced onto an ill-fitting technique.

| Technique | Name | Rules mapped (clusters) |
|---|---|---|
| **T1611** | Escape to Host | docker-socket, privileged, cap-add-all, dangerous-cap, host net/pid/ipc/userns namespaces, sensitive host-path / hostPath, host-takeover & node-compromise chains (Compose + K8s) |
| **T1552.001** | Unsecured Credentials: Credentials In Files | secret-in-env, all `SECRET-*` detectors, Dockerfile build secret, K8s secret-in-manifest, TF plaintext secret, K8s automount SA token |
| **T1552** | Unsecured Credentials (parent) | GHA `secrets: inherit`, K8s broad Secret read |
| **T1195.002** | Compromise Software Supply Chain | unpinned images/base images/actions, `curl \| sh`, remote `ADD`, disabled TLS verify, GHA pwn-request / broad-permissions / self-hosted runner |
| **T1190** | Exploit Public-Facing Application | ports on 0.0.0.0 (sensitive + any), open security group, public resource principal |
| **T1078 / T1078.001** | Valid Accounts / Default Accounts | DB auth disabled (T1078); weak/default & reachable-weak credentials (T1078.001) |
| **T1098** | Account Manipulation | cluster-admin binding, wildcard RBAC, IAM wildcard action |
| **T1562.001** | Impair Defenses: Disable or Modify Tools | seccomp/AppArmor unconfined (Compose + K8s) |
| **T1548** | Abuse Elevation Control Mechanism | allowPrivilegeEscalation, no-new-privileges missing |
| **T1059** | Command and Scripting Interpreter | GHA script injection |
| **T1530** | Data from Cloud Storage | public S3 bucket ACL |
| **T1222** | File and Directory Permissions Modification | Dockerfile world-writable (chmod 777) |
| **T1499** | Endpoint Denial of Service | no memory/resource limit |

## Verification status

- **CWE mappings: verified** against MITRE CWE across all six packs. The newer packs'
  less-common CWEs were spot-checked live against cwe.mitre.org on 2026-06-09 and all
  titles matched exactly: CWE-272 Least Privilege Violation, CWE-552 Files or Directories
  Accessible to External Parties, CWE-693 Protection Mechanism Failure, CWE-829 Inclusion
  of Functionality from Untrusted Control Sphere, CWE-1357 Reliance on Insufficiently
  Trustworthy Component, CWE-522 Insufficiently Protected Credentials, CWE-311 Missing
  Encryption of Sensitive Data, CWE-94 Improper Control of Generation of Code ('Code
  Injection'), CWE-269 Improper Privilege Management, CWE-284 Improper Access Control.
  (Notably, `IMAGE-UNPINNED` maps to **CWE-494** — pulling an image by mutable tag runs
  code without an integrity check; pinning by digest is that check. An earlier draft used
  CWE-1104, which is about *unmaintained* components and was incorrect.)
- **CIS Docker Benchmark** (Docker Compose pack): standard v1.x section identifiers;
  cross-check against your licensed CIS Docker Benchmark copy for the exact target version.
- **CIS Kubernetes Benchmark v1.10** (k8s pack): **verified** against kube-bench `cis-1.10`;
  corrected a prior off-by-one in the 5.2.x range.
- **MITRE ATT&CK (Enterprise): verified** — the container-domain techniques (T1611 Escape
  to Host, T1610 Deploy Container, T1612 Build Image on Host, T1613 Container/Resource
  Discovery, T1552.001 Credentials In Files, T1552.007 Container API) were confirmed live
  against the ATT&CK Containers matrix on 2026-06-10; the cross-domain techniques used
  (T1078/.001, T1098, T1190, T1195.002, T1499, T1530, T1548, T1552, T1059, T1222,
  T1562.001) are current Enterprise techniques. Mapping is one technique per rule (the
  primary adversary behaviour); rules with no honest technique fit are left unmapped.
