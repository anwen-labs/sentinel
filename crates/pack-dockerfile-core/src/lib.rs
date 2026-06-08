//! dockerfile-core pack — security rules for Dockerfiles. Pure functions of the
//! fact model produced by `dockerfile-parser`. See RULES.md for details.

use engine::{count_severities, Finding, Pack, Rule, Severity, Status, Verdict};
use fact_model::{EntityKind, FactModel};

pub const PACK_ID: &str = "dockerfile-core";

struct FnRule {
    id: &'static str,
    f: fn(&FactModel) -> Vec<Finding>,
}
impl Rule for FnRule {
    fn id(&self) -> &str {
        self.id
    }
    fn evaluate(&self, m: &FactModel) -> Vec<Finding> {
        (self.f)(m)
    }
}

fn finding(rule_id: &str, controls: &[&str], severity: Severity, evidence: &str, message: String, fix: &str) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        controls: controls.iter().map(|s| s.to_string()).collect(),
        severity,
        evidence: vec![evidence.to_string()],
        message,
        remediation: fix.to_string(),
    }
}

fn instr_flag(m: &FactModel, flag: &str) -> Vec<String> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Instruction)
        .filter(|e| e.attr("flag").and_then(|v| v.as_str()) == Some(flag))
        .map(|e| e.id.clone())
        .collect()
}

fn df_root_user(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Stage)
        .filter_map(|e| {
            let ra = e.attr("runs_as").and_then(|v| v.as_str())?;
            if ra == "root" || ra == "unknown" {
                let detail = if ra == "root" { "sets USER root" } else { "no USER set (defaults to root)" };
                Some(finding(
                    "DOCKERFILE-ROOT-USER",
                    &["CWE-250", "CIS-Docker-4.1"],
                    Severity::Medium,
                    &e.id,
                    format!("Image {detail} — containers should run as a non-root user"),
                    "Add a non-root `USER` instruction (and create the user) before the entrypoint.",
                ))
            } else {
                None
            }
        })
        .collect()
}

fn df_base_unpinned(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Image)
        .filter(|e| e.attr("digest_pinned").and_then(|v| v.as_bool()) == Some(false))
        .map(|e| {
            let repo = e.attr("repo").and_then(|v| v.as_str()).unwrap_or("?");
            finding(
                "DOCKERFILE-BASE-IMAGE-UNPINNED",
                &["CWE-494", "CWE-1357"],
                Severity::Low,
                &e.id,
                format!("Base image '{repo}' is not pinned by digest — the build is not reproducible"),
                "Pin the base image by digest: FROM repo@sha256:...",
            )
        })
        .collect()
}

fn df_add_remote(m: &FactModel) -> Vec<Finding> {
    instr_flag(m, "add_remote")
        .into_iter()
        .map(|id| {
            finding(
                "DOCKERFILE-ADD-REMOTE-URL",
                &["CWE-494"],
                Severity::Medium,
                &id,
                "ADD fetches a remote URL with no integrity check".into(),
                "Use COPY for local files, or RUN curl with a checksum verification step.",
            )
        })
        .collect()
}

fn df_curl_pipe(m: &FactModel) -> Vec<Finding> {
    instr_flag(m, "curl_pipe")
        .into_iter()
        .map(|id| {
            finding(
                "DOCKERFILE-CURL-PIPE-EXECUTION",
                &["CWE-494"],
                Severity::High,
                &id,
                "RUN pipes a downloaded script straight into a shell (curl | sh) — no integrity check".into(),
                "Download to a file, verify a checksum/signature, then execute.",
            )
        })
        .collect()
}

fn df_build_secret(m: &FactModel) -> Vec<Finding> {
    instr_flag(m, "secret")
        .into_iter()
        .map(|id| {
            finding(
                "DOCKERFILE-BUILD-SECRET",
                &["CWE-798"],
                Severity::Medium,
                &id,
                "A secret-like ENV/ARG has an inline value — it is baked into image layers".into(),
                "Use BuildKit secrets (RUN --mount=type=secret) or runtime env, not ENV/ARG.",
            )
        })
        .collect()
}

fn df_sudo(m: &FactModel) -> Vec<Finding> {
    instr_flag(m, "sudo")
        .into_iter()
        .map(|id| {
            finding(
                "DOCKERFILE-SUDO",
                &["CWE-250"],
                Severity::Low,
                &id,
                "RUN uses sudo — unnecessary in a build and can mask privilege issues".into(),
                "Run build steps as the appropriate user directly; drop sudo.",
            )
        })
        .collect()
}

pub struct DockerfileCorePack {
    rules: Vec<Box<dyn Rule>>,
}

impl DockerfileCorePack {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(FnRule { id: "DOCKERFILE-ROOT-USER", f: df_root_user }),
            Box::new(FnRule { id: "DOCKERFILE-BASE-IMAGE-UNPINNED", f: df_base_unpinned }),
            Box::new(FnRule { id: "DOCKERFILE-ADD-REMOTE-URL", f: df_add_remote }),
            Box::new(FnRule { id: "DOCKERFILE-CURL-PIPE-EXECUTION", f: df_curl_pipe }),
            Box::new(FnRule { id: "DOCKERFILE-BUILD-SECRET", f: df_build_secret }),
            Box::new(FnRule { id: "DOCKERFILE-SUDO", f: df_sudo }),
        ];
        Self { rules }
    }
}

impl Default for DockerfileCorePack {
    fn default() -> Self {
        Self::new()
    }
}

impl Pack for DockerfileCorePack {
    fn id(&self) -> &str {
        PACK_ID
    }
    fn rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }
    fn verdict(&self, findings: &[Finding]) -> Verdict {
        let counts = count_severities(findings);
        let status = if counts.critical > 0 || counts.high > 0 {
            Status::FlaggedGap
        } else {
            Status::Cleared
        };
        Verdict {
            counts,
            status,
            pack_policy: "any Critical or High => Flagged-Gap".to_string(),
        }
    }
}
