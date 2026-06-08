//! Engine core: findings, verdict, the `Rule` / `Pack` traits, and the
//! content-addressed report (ADR 0003).
#![allow(dead_code)]

use fact_model::{sha256_hex, sha256_prefixed, FactModel, Json};

pub const ENGINE_VERSION: &str = "0.1.0";

/// Severity, ordered so that `Critical` is greatest (for descending sort).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub controls: Vec<String>,
    pub severity: Severity,
    pub evidence: Vec<String>,
    pub message: String,
    pub remediation: String,
}

/// Shared status vocabulary (DESIGN_SYSTEM.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    InReview,
    FlaggedGap,
    Cleared,
    Escalated,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::InReview => "in_review",
            Status::FlaggedGap => "flagged_gap",
            Status::Cleared => "cleared",
            Status::Escalated => "escalated",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub counts: SeverityCounts,
    pub status: Status,
    pub pack_policy: String,
}

/// A deterministic rule: a pure function of the fact model.
pub trait Rule {
    fn id(&self) -> &str;
    fn evaluate(&self, model: &FactModel) -> Vec<Finding>;
}

/// A pack: a versioned set of rules plus a deterministic verdict policy.
pub trait Pack {
    fn id(&self) -> &str;
    fn rules(&self) -> &[Box<dyn Rule>];
    fn verdict(&self, findings: &[Finding]) -> Verdict;
}

/// Run every rule and return findings in canonical order
/// (severity desc, then rule_id, then evidence) per ADR 0003.
pub fn run_pack(pack: &dyn Pack, model: &FactModel) -> Vec<Finding> {
    let mut findings: Vec<Finding> = pack
        .rules()
        .iter()
        .flat_map(|r| r.evaluate(model))
        .collect();
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.evidence.cmp(&b.evidence))
    });
    findings
}

pub fn count_severities(findings: &[Finding]) -> SeverityCounts {
    let mut c = SeverityCounts::default();
    for f in findings {
        match f.severity {
            Severity::Critical => c.critical += 1,
            Severity::High => c.high += 1,
            Severity::Medium => c.medium += 1,
            Severity::Low => c.low += 1,
            Severity::Info => c.info += 1,
        }
    }
    c
}

/// Deterministic pack version: hash of sorted rule ids + policy.
pub fn pack_version_hash(pack: &dyn Pack) -> String {
    let mut ids: Vec<String> = pack.rules().iter().map(|r| r.id().to_string()).collect();
    ids.sort();
    sha256_prefixed(ids.join(",").as_bytes())
}

/// Placeholder build digest. TODO(P1): replace with a real hermetic build hash.
pub fn engine_build_digest() -> String {
    sha256_prefixed(format!("engine-{}-skeleton", ENGINE_VERSION).as_bytes())
}

// ---------------------------------------------------------------------------
// Content-addressed report (ADR 0003)
// ---------------------------------------------------------------------------

fn finding_to_json(f: &Finding) -> Json {
    let mut controls = f.controls.clone();
    controls.sort();
    let mut evidence = f.evidence.clone();
    evidence.sort();
    Json::Obj(vec![
        ("rule_id".into(), Json::Str(f.rule_id.clone())),
        (
            "controls".into(),
            Json::Arr(controls.into_iter().map(Json::Str).collect()),
        ),
        ("severity".into(), Json::Str(f.severity.as_str().into())),
        (
            "evidence".into(),
            Json::Arr(evidence.into_iter().map(Json::Str).collect()),
        ),
        ("message".into(), Json::Str(f.message.clone())),
        ("remediation".into(), Json::Str(f.remediation.clone())),
    ])
}

fn verdict_to_json(v: &Verdict) -> Json {
    Json::Obj(vec![
        (
            "counts".into(),
            Json::Obj(vec![
                ("critical".into(), Json::Int(v.counts.critical as i64)),
                ("high".into(), Json::Int(v.counts.high as i64)),
                ("medium".into(), Json::Int(v.counts.medium as i64)),
                ("low".into(), Json::Int(v.counts.low as i64)),
                ("info".into(), Json::Int(v.counts.info as i64)),
            ]),
        ),
        ("status".into(), Json::Str(v.status.as_str().into())),
        ("pack_policy".into(), Json::Str(v.pack_policy.clone())),
    ])
}

/// The hashed core of a report. `report_digest = sha256(canonical_json(core))`.
pub struct ReportCore<'a> {
    pub model: &'a FactModel,
    pub pack_id: String,
    pub pack_version_hash: String,
    pub findings: &'a [Finding],
    pub verdict: &'a Verdict,
}

impl<'a> ReportCore<'a> {
    pub fn to_canonical_json(&self) -> Json {
        Json::Obj(vec![
            ("schema_version".into(), Json::Str("0".into())),
            (
                "input".into(),
                Json::Obj(vec![
                    ("kind".into(), Json::Str(self.model.source.kind.clone())),
                    ("input_hash".into(), Json::Str(self.model.source.input_hash.clone())),
                ]),
            ),
            ("model_hash".into(), Json::Str(self.model.model_hash())),
            (
                "engine".into(),
                Json::Obj(vec![
                    ("version".into(), Json::Str(ENGINE_VERSION.into())),
                    ("build_digest".into(), Json::Str(engine_build_digest())),
                ]),
            ),
            (
                "packs".into(),
                Json::Arr(vec![Json::Obj(vec![
                    ("id".into(), Json::Str(self.pack_id.clone())),
                    ("version_hash".into(), Json::Str(self.pack_version_hash.clone())),
                ])]),
            ),
            (
                "findings".into(),
                Json::Arr(self.findings.iter().map(finding_to_json).collect()),
            ),
            ("verdict".into(), verdict_to_json(self.verdict)),
        ])
    }

    /// `"sha256:" + sha256(canonical_json(core))`.
    pub fn report_digest(&self) -> String {
        format!(
            "sha256:{}",
            sha256_hex(self.to_canonical_json().to_canonical_string().as_bytes())
        )
    }
}

/// Build the full report JSON: a non-hashed `envelope` wrapping the hashed
/// `core` (ADR 0003). `report_id` and `generated_at_unix` are operational
/// metadata and are deliberately NOT part of the digest.
pub fn full_report_json(core: &ReportCore, report_id: &str, generated_at_unix: i64) -> Json {
    Json::Obj(vec![
        (
            "envelope".into(),
            Json::Obj(vec![
                ("report_id".into(), Json::Str(report_id.to_string())),
                ("generated_at_unix".into(), Json::Int(generated_at_unix)),
                ("report_digest".into(), Json::Str(core.report_digest())),
            ]),
        ),
        ("core".into(), core.to_canonical_json()),
    ])
}
