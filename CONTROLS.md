# Control mappings

Every Sentinel finding cites the standards it maps to. This table documents those
mappings and their basis.

**Scope — technical controls, not certifications.** Sentinel maps each finding to specific
*technical controls* (CWE, CIS Benchmarks, MITRE ATT&CK, and — being added — NIST SP
800-53/171 and PCI DSS). A finding contributes **evidence toward** a named control; it does
not assess a management system or certify regulatory compliance. Sentinel does not — and
cannot honestly — badge ISO 27001, SOC 2, ISO 42001, HIPAA, GDPR, the EU AI Act, NIS2, or
DORA: those are management-system attestations or binding regulations, not technical controls
a deterministic config scanner can verify. Use Sentinel as evidence *toward* such programs,
never as a substitute for their audit/attestation.

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

## NIST SP 800-53 Rev 5 / SP 800-171

NIST mappings extend the control story for the gov/defense pipeline-gating audience. Each
finding maps to the **800-53 Rev 5** control(s) it provides *evidence toward* (not a compliance
claim — see Scope above), with the **800-171 r2** CUI requirement noted where the control is in
that subset. Every mapping below was proposed and then **independently verified against the
official 800-53 Rev 5 catalog** (csrc.nist.gov / OSCAL); _(partial)_ marks a control the finding
contributes to but does not fully determine. Over-broad candidates were dropped in verification
(CM-6 for weak credentials; SR-11 for unpinned images). Five rules have no genuine 800-53 fit
and are left unmapped: `NO-NEW-PRIVILEGES-MISSING`, `K8S-READONLY-ROOTFS-MISSING`,
`K8S-ALLOW-PRIV-ESC-NOT-DISABLED`, `GHA-SELF-HOSTED-RUNNER`, `DOCKERFILE-SUDO`.

### Docker Compose pack

| Rule | Severity | NIST SP 800-53 Rev 5 | 800-171 r2 |
|---|---|---|---|
| `DOCKER-SOCKET-MOUNT` | Critical | AC-6 Least Privilege; CM-7 Least Functionality | 3.1.5, 3.4.6 |
| `REACHABLE-HOST-TAKEOVER` | Critical | SC-7 Boundary Protection; SC-39 Process Isolation _(partial)_; AC-6 Least Privilege _(partial)_ | 3.13.1, 3.1.5 |
| `PRIVILEGED-CONTAINER` | Critical | AC-6 Least Privilege; SC-39 Process Isolation; CM-7 Least Functionality _(partial)_ | 3.1.5 |
| `CAP-ADD-ALL` | Critical | AC-6 Least Privilege; CM-7 Least Functionality _(partial)_ | 3.1.5 |
| `DANGEROUS-CAPABILITY` | High | AC-6 Least Privilege _(partial)_; SC-39 Process Isolation _(partial)_ | 3.1.5 |
| `HOST-NETWORK-MODE` | High | SC-7 Boundary Protection; SC-39 Process Isolation _(partial)_ | 3.13.1 |
| `WEAK-DEFAULT-CREDENTIAL` | High | IA-5 Authenticator Management; IA-5(1) Password-based Authentication | 3.5.2, 3.5.7 |
| `DATABASE-AUTH-DISABLED` | High | IA-2 Identification and Authentication (Org Users); IA-5 Authenticator Management _(partial)_ | 3.5.2 |
| `HOST-PID-NAMESPACE` | High | SC-39 Process Isolation | — |
| `HOST-IPC-NAMESPACE` | High | SC-39 Process Isolation _(partial)_; SC-4 Information in Shared System Resources _(partial)_ | 3.13.4 |
| `SECURITY-PROFILE-DISABLED` | High | CM-7 Least Functionality | 3.4.6 |
| `HOST-USERNS-MODE` | High | SC-39 Process Isolation; AC-6 Least Privilege | 3.1.5 |
| `SENSITIVE-HOST-PATH-MOUNT` | High | SC-39 Process Isolation; AC-6 Least Privilege _(partial)_; CM-7 Least Functionality _(partial)_ | 3.4.6, 3.1.5 |
| `REACHABLE-WEAK-CREDENTIAL` | High | IA-5 Authenticator Management; IA-5(1) Password-Based Authentication | 3.5.2, 3.5.7 |
| `SECRET-IN-ENVIRONMENT` | Medium | IA-5(7) No Embedded Unencrypted Static Authenticators; IA-5 Authenticator Management _(partial)_ | — |
| `SENSITIVE-PORT-PUBLISHED-ALL-IFACES` | Medium | SC-7 Boundary Protection; SC-7(5) Deny by Default; CM-7 Least Functionality _(partial)_ | 3.13.1, 3.13.6, 3.4.7 |
| `CONTAINER-RUNS-AS-ROOT-OR-UNKNOWN` | Low | AC-6 Least Privilege _(partial)_ | 3.1.5 |
| `IMAGE-UNPINNED` | Low | SR-4 Provenance _(partial)_; CM-14 Signed Components _(partial)_ | — |
| `WRITABLE-ROOT-FILESYSTEM` | Low | AC-6 Least Privilege; AC-3 Access Enforcement _(partial)_ | 3.1.5 |
| `PORT-PUBLISHED-ALL-IFACES` | Low | CM-7 Least Functionality; SC-7 Boundary Protection _(partial)_ | 3.4.6, 3.13.1 |
| `CAP-DROP-ALL-MISSING` | Low | CM-7 Least Functionality _(partial)_; AC-6 Least Privilege _(partial)_ | 3.4.6, 3.1.5 |
| `NO-RESOURCE-LIMITS` | Low | SC-6 Resource Availability; SC-5 Denial-of-service Protection _(partial)_ | — |

### Kubernetes pack

| Rule | Severity | NIST SP 800-53 Rev 5 | 800-171 r2 |
|---|---|---|---|
| `K8S-REACHABLE-NODE-COMPROMISE` | Critical | SC-7 Boundary Protection; AC-6 Least Privilege _(partial)_ | 3.13.1, 3.1.5 |
| `K8S-PRIVILEGED-CONTAINER` | Critical | AC-6 Least Privilege; SC-39 Process Isolation; CM-7 Least Functionality _(partial)_ | 3.1.5 |
| `K8S-CAP-ADD-ALL` | Critical | AC-6(1) Authorize Access to Security Functions | 3.1.5 |
| `K8S-CLUSTER-ADMIN-BINDING` | Critical | AC-6 Least Privilege; AC-3 Access Enforcement _(partial)_ | 3.1.5, 3.1.2 |
| `K8S-HOST-NETWORK` | High | SC-7 Boundary Protection | 3.13.1 |
| `K8S-HOST-PID` | High | SC-39 Process Isolation; CM-6 Configuration Settings _(partial)_ | 3.4.2 |
| `K8S-HOST-IPC` | High | SC-39 Process Isolation | — |
| `K8S-HOSTPATH-MOUNT` | High | SC-39 Process Isolation; CM-7 Least Functionality _(partial)_; AC-6 Least Privilege _(partial)_ | 3.4.6, 3.1.5 |
| `K8S-DANGEROUS-CAPABILITY` | High | AC-6 Least Privilege; CM-7 Least Functionality _(partial)_ | 3.1.5, 3.4.6 |
| `K8S-SECCOMP-UNCONFINED` | High | CM-7 Least Functionality; SC-39 Process Isolation _(partial)_ | 3.4.6 |
| `K8S-RBAC-WILDCARD` | High | AC-6 Least Privilege; AC-3 Access Enforcement _(partial)_ | 3.1.5, 3.1.2 |
| `K8S-RBAC-SECRET-READ` | Medium | AC-6 Least Privilege; AC-3 Access Enforcement _(partial)_ | 3.1.5, 3.1.2 |
| `K8S-ALLOW-PRIVILEGE-ESCALATION` | Medium | AC-6 Least Privilege; AC-6(10) Prohibit Non-Privileged Users _(partial)_ | 3.1.5, 3.1.7 |
| `K8S-SECRET-IN-MANIFEST` | Medium | IA-5(7) No Embedded Unencrypted Static Authenticators; IA-5 Authenticator Management _(partial)_ | 3.5.2 |
| `K8S-IMAGE-UNPINNED` | Low | SI-7 Software, Firmware, and Information Integrity _(partial)_; SR-4 Provenance _(partial)_ | — |
| `K8S-CONTAINER-RUNS-AS-ROOT` | Low | AC-6 Least Privilege _(partial)_ | 3.1.5 |
| `K8S-AUTOMOUNT-SA-TOKEN` | Low | AC-6 Least Privilege | 3.1.5 |

### Secrets pack

| Rule | Severity | NIST SP 800-53 Rev 5 | 800-171 r2 |
|---|---|---|---|
| `SECRET-AWS-ACCESS-KEY` | High | IA-5(7) No Embedded Unencrypted Static Authenticators; IA-5 Authenticator Management _(partial)_ | 3.5.10 |
| `SECRET-PRIVATE-KEY` | High | IA-5(7) No Embedded Unencrypted Static Authenticators; SC-12 Cryptographic Key Establishment and Management _(partial)_; IA-5 Authenticator Management _(partial)_ | 3.13.10 |
| `SECRET-GITHUB-TOKEN` | High | IA-5(7) No Embedded Unencrypted Static Authenticators; IA-5 Authenticator Management _(partial)_ | 3.5.10 |
| `SECRET-SLACK-TOKEN` | High | IA-5(7) No Embedded Unencrypted Static Authenticators | — |
| `SECRET-STRIPE-KEY` | High | IA-5(7) No Embedded Unencrypted Static Authenticators; IA-5 Authenticator Management _(partial)_ | 3.5.2 |
| `SECRET-SENDGRID-KEY` | High | IA-5(7) No Embedded Unencrypted Static Authenticators; IA-5 Authenticator Management _(partial)_ | 3.5.2 |
| `SECRET-GOOGLE-API-KEY` | Medium | IA-5(7) No Embedded Unencrypted Static Authenticators | — |
| `SECRET-GENERIC-CREDENTIAL` | Medium | IA-5(7) No Embedded Unencrypted Static Authenticators; IA-5 Authenticator Management _(partial)_ | — |

### GitHub Actions pack

| Rule | Severity | NIST SP 800-53 Rev 5 | 800-171 r2 |
|---|---|---|---|
| `GHA-PWN-REQUEST` | Critical | AC-6 Least Privilege; CM-7 Least Functionality _(partial)_ | 3.1.5, 3.4.6 |
| `GHA-SCRIPT-INJECTION` | High | SI-10 Information Input Validation | — |
| `GHA-BROAD-PERMISSIONS` | Medium | AC-6 Least Privilege; CM-7 Least Functionality _(partial)_ | 3.1.5, 3.4.6 |
| `GHA-SECRETS-INHERIT` | Medium | AC-6 Least Privilege | 3.1.5 |
| `GHA-UNPINNED-ACTION` | Low | SR-11 Component Authenticity; SR-4 Provenance _(partial)_; SI-7 Software, Firmware, and Information Integrity _(partial)_ | — |

### Terraform pack

| Rule | Severity | NIST SP 800-53 Rev 5 | 800-171 r2 |
|---|---|---|---|
| `TF-OPEN-SECURITY-GROUP` | High | SC-7 Boundary Protection; AC-4 Information Flow Enforcement _(partial)_ | 3.13.1, 3.1.3 |
| `TF-PUBLIC-S3-BUCKET` | High | AC-3 Access Enforcement; AC-6 Least Privilege _(partial)_ | 3.1.1, 3.1.5 |
| `TF-IAM-WILDCARD-ACTION` | High | AC-6 Least Privilege; AC-6(1) Authorize Access to Security Functions; AC-6(5) Privileged Accounts _(partial)_ | 3.1.5 |
| `TF-IAM-PUBLIC-PRINCIPAL` | High | AC-6 Least Privilege; AC-3 Access Enforcement _(partial)_ | 3.1.5, 3.1.2 |
| `TF-PLAINTEXT-SECRET` | High | IA-5(7) No Embedded Unencrypted Static Authenticators; IA-5 Authenticator Management _(partial)_ | 3.5.10 |
| `TF-UNENCRYPTED-STORAGE` | Medium | SC-28 Protection of Information at Rest; SC-28(1) Cryptographic Protection | 3.13.16 |

### Dockerfile pack

| Rule | Severity | NIST SP 800-53 Rev 5 | 800-171 r2 |
|---|---|---|---|
| `DOCKERFILE-CURL-PIPE-EXECUTION` | High | CM-14 Signed Components _(partial)_; SI-7 Software, Firmware, and Information Integrity _(partial)_ | — |
| `DOCKERFILE-TLS-VERIFICATION-DISABLED` | High | SC-23 Session Authenticity; SC-8 Transmission Confidentiality and Integrity _(partial)_ | 3.13.15, 3.13.8 |
| `DOCKERFILE-WORLD-WRITABLE` | Medium | AC-6 Least Privilege; AC-3 Access Enforcement _(partial)_ | 3.1.5, 3.1.2 |
| `DOCKERFILE-ROOT-USER` | Medium | AC-6 Least Privilege | 3.1.5 |
| `DOCKERFILE-ADD-REMOTE-URL` | Medium | SI-7 Software, Firmware, and Information Integrity; CM-14 Signed Components _(partial)_ | — |
| `DOCKERFILE-BUILD-SECRET` | Medium | IA-5(7) No Embedded Unencrypted Static Authenticators; IA-5 Authenticator Management _(partial)_ | 3.5.2 |
| `DOCKERFILE-BASE-IMAGE-UNPINNED` | Low | SI-7 Software, Firmware, and Information Integrity | — |

Controls outside the 800-171 r2 CUI subset carry no 800-171 number (shown as — when all controls on a row are outside the subset): SC-39, SC-6, SC-5 (availability/tailored-out), IA-5(7) (no-baseline enhancement), CM-14, SR-4, SR-11 (Supply-Chain-family, new in Rev 5 only), SI-7, SI-10, SC-4, CM-6, AC-6(10), SC-8, SC-28(1) (enhancement only; base SC-28 carries 3.13.16).

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
- **NIST SP 800-53 Rev 5 / 800-171 (all rules): verified** — every mapping across all 70
  rules was proposed and independently re-checked against the official 800-53 Rev 5 catalog
  (csrc.nist.gov / OSCAL) for exact id/family/title and genuine evidentiary fit; over-broad
  candidates (CM-6 for weak credentials, SR-11 for unpinned images) were dropped and weak
  links marked _(partial)_. Five rules with no genuine 800-53 fit are left unmapped
  (see section header). 800-171 numbers are Rev 2.
