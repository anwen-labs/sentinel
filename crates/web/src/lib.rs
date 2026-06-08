//! WASM bindings for the Sentinel engine — runs the full deterministic scan
//! entirely in the browser. No network, no server: the compose text never
//! leaves the page.

use wasm_bindgen::prelude::*;

use compose_parser::try_parse;
use engine::{full_report_json, pack_version_hash, run_pack, Pack, ReportCore};
use fact_model::Json;
use pack_sentinel_core::SentinelCorePack;

/// Scan Docker Compose text and return the full report as a JSON string
/// (envelope + content-addressed core). On invalid YAML, returns
/// `{"error":"..."}`.
#[wasm_bindgen]
pub fn scan(input: &str) -> String {
    let model = match try_parse(input) {
        Ok(m) => m,
        Err(e) => {
            return Json::Obj(vec![("error".into(), Json::Str(e))]).to_canonical_string();
        }
    };

    let pack = SentinelCorePack::new();
    let findings = run_pack(&pack, &model);
    let verdict = pack.verdict(&findings);

    let core = ReportCore {
        model: &model,
        pack_id: pack.id().to_string(),
        pack_version_hash: pack_version_hash(&pack),
        findings: &findings,
        verdict: &verdict,
    };
    let digest = core.report_digest();
    let report_id = format!(
        "rpt_{}",
        digest.trim_start_matches("sha256:").get(..12).unwrap_or("")
    );
    // No wall clock in WASM; the timestamp is non-hashed envelope metadata.
    full_report_json(&core, &report_id, 0).to_canonical_string()
}

/// Engine version (for display).
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
