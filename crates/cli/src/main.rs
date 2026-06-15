//! `sentinel` — deterministic security scanner for infrastructure configs
//! (Docker Compose, Dockerfile, Kubernetes, GitHub Actions, Terraform, secrets).
//!
//!   sentinel scan docker-compose.yml          # a single file (type auto-detected)
//!   sentinel scan ./my-repo                    # a whole directory (every config under it)
//!   cat Dockerfile | sentinel scan - --type dockerfile
//!   sentinel scan compose.yml --format sarif --fail-on high

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use engine::{
    count_severities, detect_input, full_report_json, pack_version_hash, run_pack, sarif_json,
    Finding, InputKind, Pack, ReportCore, Severity,
};
use fact_model::{FactModel, Json};
use pack_dockerfile_core::DockerfileCorePack;
use pack_gha_core::GhaCorePack;
use pack_k8s_core::K8sCorePack;
use pack_secrets_core::SecretsCorePack;
use pack_sentinel_core::SentinelCorePack;
use pack_terraform_core::TerraformCorePack;

#[derive(Clone, Copy, ValueEnum)]
enum InputType {
    /// Auto-detect from filename/content.
    Auto,
    Compose,
    Dockerfile,
    Kubernetes,
    #[value(name = "github-actions")]
    GithubActions,
    Terraform,
    Secrets,
}

/// Parse the input and pick the matching rule pack.
fn build_model_and_pack(
    input: &str,
    kind: InputType,
    path: &str,
    strict: bool,
) -> Result<(FactModel, Box<dyn Pack>), String> {
    // Boundary size cap — covers every format uniformly, including the
    // fail-open parsers (Dockerfile/Terraform/secrets) that don't return Result.
    fact_model::limits::check_input_size(input)?;
    let resolved = match kind {
        InputType::Auto => detect_input(path, input),
        InputType::Compose => InputKind::Compose,
        InputType::Dockerfile => InputKind::Dockerfile,
        InputType::Kubernetes => InputKind::Kubernetes,
        InputType::GithubActions => InputKind::GithubActions,
        InputType::Terraform => InputKind::Terraform,
        InputType::Secrets => InputKind::Secrets,
    };
    match resolved {
        InputKind::Dockerfile => Ok((
            dockerfile_parser::parse(input),
            Box::new(DockerfileCorePack::new()),
        )),
        InputKind::Kubernetes => Ok((
            k8s_parser::try_parse(input)?,
            Box::new(K8sCorePack::with_options(strict)),
        )),
        InputKind::GithubActions => Ok((
            gha_parser::try_parse(input)?,
            Box::new(GhaCorePack::new()),
        )),
        InputKind::Terraform => Ok((
            terraform_parser::try_parse(input)?,
            Box::new(TerraformCorePack::new()),
        )),
        InputKind::Secrets => Ok((
            secrets_parser::parse(input),
            Box::new(SecretsCorePack::new()),
        )),
        InputKind::Compose => Ok((
            compose_parser::try_parse(input)?,
            Box::new(SentinelCorePack::with_options(strict)),
        )),
    }
}

#[derive(Parser)]
#[command(
    name = "sentinel",
    version,
    about = "Deterministic security scanner (Docker Compose, Dockerfile, Kubernetes, GitHub Actions, Terraform, secrets)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a Docker Compose file for security misconfigurations.
    Scan(ScanArgs),
    /// Re-check that a saved JSON report reproduces its digest for a compose file.
    Verify(VerifyArgs),
    /// Print the full rule catalog as Markdown (the source of truth for RULES.md).
    Rules(RulesArgs),
}

#[derive(Args)]
struct RulesArgs {
    /// Emit the catalog as JSON instead of Markdown.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct VerifyArgs {
    /// Path to a saved JSON report (from `sentinel scan --format json`).
    report: String,
    /// Path to the file to re-scan, or "-" to read from stdin.
    compose: String,
    /// Input type (auto-detected by default).
    #[arg(long, value_enum, default_value_t = InputType::Auto)]
    r#type: InputType,
    /// Use the strict rule set (must match how the report was produced).
    #[arg(long)]
    strict: bool,
}

#[derive(Args)]
struct ScanArgs {
    /// Path to a compose file or Dockerfile, or "-" to read from stdin.
    path: String,

    /// Input type (auto-detected by default).
    #[arg(long, value_enum, default_value_t = InputType::Auto)]
    r#type: InputType,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Exit non-zero if any finding is at or above this severity (for CI).
    #[arg(long, value_name = "SEVERITY")]
    fail_on: Option<SeverityArg>,

    /// Only print the verdict line and digest.
    #[arg(long)]
    quiet: bool,

    /// Include best-practice hardening rules (no-new-privileges, cap-drop, memory limits).
    #[arg(long)]
    strict: bool,
}

#[derive(Clone, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Critical => Severity::Critical,
            SeverityArg::High => Severity::High,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Info => Severity::Info,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => scan(args),
        Command::Verify(args) => verify(args),
        Command::Rules(args) => rules(args),
    }
}

/// Every shipped rule, in reader-friendly target order (compose → secrets).
/// Order drives RULES.md section order only; rule ids are unique so anchors
/// never collide.
fn all_catalog() -> Vec<engine::RuleMeta> {
    let mut metas = pack_sentinel_core::catalog();
    metas.extend(pack_dockerfile_core::catalog());
    metas.extend(pack_k8s_core::catalog());
    metas.extend(pack_gha_core::catalog());
    metas.extend(pack_terraform_core::catalog());
    metas.extend(pack_secrets_core::catalog());
    metas
}

fn rules(args: RulesArgs) -> ExitCode {
    let metas = all_catalog();
    if args.json {
        println!("{}", engine::catalog_json(&metas).to_canonical_string());
    } else {
        print!("{}", engine::catalog_md(&metas));
    }
    ExitCode::SUCCESS
}

fn read_input(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("cannot read stdin: {e}"))?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))
    }
}

/// Detect Go-template / Jinja templating (Helm charts, Kustomize-with-templates,
/// Ansible) — not valid YAML/HCL as written, so the parser can't read it. GitHub
/// Actions `${{ }}` expressions are deliberately excluded (the leading `$`).
fn looks_templated(input: &str) -> bool {
    let b = input.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'{' && b[i + 1] == b'{' && (i == 0 || b[i - 1] != b'$') {
            return true;
        }
        i += 1;
    }
    false
}

/// Decide whether to reject an input as an un-renderable templated manifest.
///
/// The guard exists to give a clear error for Helm/Kustomize/Ansible YAML the
/// parser can't read. It must NOT fire for GitHub Actions: bare `{{ }}` is
/// legitimate there (e.g. docker/metadata-action's `enable={{is_default_branch}}`
/// and `{{version}}`/`{{date}}` tag templates). An explicit `--type` also wins —
/// the caller has asserted the format, and the parser surfaces a real error if
/// they're wrong — so the guard only applies to auto-detected, non-GHA input.
fn rejected_as_templated(kind: InputType, path: &str, input: &str) -> bool {
    if !matches!(kind, InputType::Auto) {
        return false; // explicit --type: trust the caller
    }
    if matches!(detect_input(path, input), InputKind::GithubActions) {
        return false; // auto-detected GitHub Actions: bare {{ }} is valid
    }
    looks_templated(input)
}

fn scan(args: ScanArgs) -> ExitCode {
    // A directory path → whole-repo scan (every config file under it).
    if args.path != "-" && std::path::Path::new(&args.path).is_dir() {
        return scan_dir(args);
    }

    let input = match read_input(&args.path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    // Templated manifests can't be scanned as-is — fail clearly rather than
    // emit a misleading parse error or a false-clean result. GitHub Actions
    // (bare {{ }} tag templates) and explicit --type are exempt.
    if rejected_as_templated(args.r#type, &args.path, &input) {
        eprintln!(
            "error: {} looks like a templated manifest (Helm/Kustomize Go-template syntax). \
             Render it first (e.g. `helm template . | sentinel scan -`) and scan the output.",
            args.path
        );
        return ExitCode::from(2);
    }

    let (model, pack) = match build_model_and_pack(&input, args.r#type, &args.path, args.strict) {
        Ok(mp) => mp,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let mut findings = run_pack(pack.as_ref(), &model);
    // Attach source lines for text/SARIF output. Excluded from the hashed core,
    // so the report digest is unaffected.
    engine::attach_lines(&mut findings, &model);
    let verdict = pack.verdict(&findings);

    let core = ReportCore {
        model: &model,
        pack_id: pack.id().to_string(),
        pack_version_hash: pack_version_hash(pack.as_ref()),
        findings: &findings,
        verdict: &verdict,
    };
    let digest = core.report_digest();
    let report_id = format!("rpt_{}", digest.trim_start_matches("sha256:").get(..12).unwrap_or(""));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    match args.format {
        Format::Json => {
            println!(
                "{}",
                full_report_json(&core, &report_id, now).to_canonical_string()
            );
        }
        Format::Sarif => {
            let uri = if args.path == "-" { "docker-compose.yml" } else { args.path.as_str() };
            println!("{}", sarif_json(&findings, uri).to_canonical_string());
        }
        Format::Text => print_text(&args, pack.id(), &model, &findings, &verdict, &digest),
    }

    // CI gate: exit non-zero if any finding >= fail-on threshold.
    if let Some(threshold) = args.fail_on {
        let threshold: Severity = threshold.into();
        if findings.iter().any(|f| f.severity >= threshold) {
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}

// Directories that never hold first-party config worth scanning.
const IGNORE_DIRS: &[&str] = &[
    ".git", "node_modules", "target", "vendor", "dist", "build", ".terraform", ".next",
    ".venv", "venv", "__pycache__", ".idea", ".vscode", ".mypy_cache",
];

/// Does this filename look like a config Sentinel can scan? (Type is still
/// auto-detected per file; this is just the walk filter.)
fn is_scannable_candidate(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name == "dockerfile" || name.ends_with(".dockerfile") || name.starts_with("dockerfile.") {
        return true;
    }
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    matches!(
        path.extension().and_then(|s| s.to_str()).map(|s| s.to_ascii_lowercase()).as_deref(),
        Some("tf") | Some("yml") | Some("yaml") | Some("env")
    )
}

/// Depth-first, deterministic collection of candidate files under `root`,
/// skipping vendored/build dirs and hidden dirs (except `.github`).
fn collect_candidates(root: &Path, out: &mut Vec<PathBuf>) {
    let rd = match std::fs::read_dir(root) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    let (mut dirs, mut files) = (Vec::new(), Vec::new());
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let dn = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if IGNORE_DIRS.contains(&dn) || (dn.starts_with('.') && dn != ".github") {
                continue;
            }
            dirs.push(p);
        } else if p.is_file() && is_scannable_candidate(&p) {
            files.push(p);
        }
    }
    files.sort();
    dirs.sort();
    out.extend(files);
    for d in dirs {
        collect_candidates(&d, out);
    }
}

struct FileResult {
    rel: String,
    kind: String,
    findings: Vec<Finding>,
    status: String,
    digest: String,
    report: Json,
}

/// Whole-repo scan: walk a directory, scan every config file, aggregate.
/// Type is auto-detected per file (an explicit `--type` is ignored for dirs,
/// since a tree holds mixed formats).
fn scan_dir(args: ScanArgs) -> ExitCode {
    if matches!(args.format, Format::Sarif) {
        eprintln!(
            "error: SARIF output isn't supported for directory scans yet; scan a single file \
             for SARIF, or use --format json for the whole tree."
        );
        return ExitCode::from(2);
    }
    let root = Path::new(&args.path);
    let mut candidates = Vec::new();
    collect_candidates(root, &mut candidates);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut results: Vec<FileResult> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();

    for path in &candidates {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let input = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                skipped.push((rel, format!("unreadable: {e}")));
                continue;
            }
        };
        if looks_templated(&input) {
            skipped.push((rel, "templated (Helm/Kustomize) — render before scanning".into()));
            continue;
        }
        match build_model_and_pack(&input, InputType::Auto, &path.to_string_lossy(), args.strict) {
            Ok((model, pack)) => {
                // Skip files that parsed to nothing (e.g. a non-config YAML) so
                // the report only lists real, assessed targets.
                if model.entities.is_empty() {
                    continue;
                }
                let mut findings = run_pack(pack.as_ref(), &model);
                engine::attach_lines(&mut findings, &model);
                let verdict = pack.verdict(&findings);
                let core = ReportCore {
                    model: &model,
                    pack_id: pack.id().to_string(),
                    pack_version_hash: pack_version_hash(pack.as_ref()),
                    findings: &findings,
                    verdict: &verdict,
                };
                let digest = core.report_digest();
                let report_id =
                    format!("rpt_{}", digest.trim_start_matches("sha256:").get(..12).unwrap_or(""));
                let report = full_report_json(&core, &report_id, now);
                let status = verdict.status.as_str().to_string();
                results.push(FileResult { rel, kind: model.source.kind.clone(), findings, status, digest, report });
            }
            Err(e) => skipped.push((rel, e)),
        }
    }

    let all: Vec<&Finding> = results.iter().flat_map(|r| r.findings.iter()).collect();
    let owned: Vec<Finding> = all.into_iter().cloned().collect();
    let counts = count_severities(&owned);
    let flagged = counts.critical > 0 || counts.high > 0;
    let status = if flagged { "FLAGGED_GAP" } else { "CLEARED" };

    if matches!(args.format, Format::Json) {
        let files: Vec<Json> = results
            .iter()
            .map(|r| {
                Json::Obj(vec![
                    ("path".into(), Json::Str(r.rel.clone())),
                    ("kind".into(), Json::Str(r.kind.clone())),
                    ("report".into(), r.report.clone()),
                ])
            })
            .collect();
        let skipped_json: Vec<Json> = skipped
            .iter()
            .map(|(p, reason)| {
                Json::Obj(vec![
                    ("path".into(), Json::Str(p.clone())),
                    ("reason".into(), Json::Str(reason.clone())),
                ])
            })
            .collect();
        let out = Json::Obj(vec![
            ("schema_version".into(), Json::Str("0".into())),
            ("root".into(), Json::Str(args.path.clone())),
            ("files".into(), Json::Arr(files)),
            ("skipped".into(), Json::Arr(skipped_json)),
            (
                "summary".into(),
                Json::Obj(vec![
                    ("files_scanned".into(), Json::Int(results.len() as i64)),
                    ("files_skipped".into(), Json::Int(skipped.len() as i64)),
                    ("status".into(), Json::Str(status.to_lowercase())),
                    (
                        "counts".into(),
                        Json::Obj(vec![
                            ("critical".into(), Json::Int(counts.critical as i64)),
                            ("high".into(), Json::Int(counts.high as i64)),
                            ("medium".into(), Json::Int(counts.medium as i64)),
                            ("low".into(), Json::Int(counts.low as i64)),
                            ("info".into(), Json::Int(counts.info as i64)),
                        ]),
                    ),
                ]),
            ),
        ]);
        println!("{}", out.to_canonical_string());
    } else {
        println!("sentinel {} — repo scan: {}", env!("CARGO_PKG_VERSION"), args.path);
        let with = results.iter().filter(|r| !r.findings.is_empty()).count();
        println!(
            "scanned {} file(s), {} with findings, {} skipped\n",
            results.len(),
            with,
            skipped.len()
        );
        for r in &results {
            if r.findings.is_empty() {
                continue;
            }
            println!("── {} ({}) — {} ──", r.rel, r.kind, r.status);
            for f in &r.findings {
                let loc = match f.lines.as_slice() {
                    [] => String::new(),
                    [l] => format!("  (line {l})"),
                    ls => format!(
                        "  (lines {})",
                        ls.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", ")
                    ),
                };
                println!("  [{:<8}] {:<34} {}{loc}", f.severity.as_str(), f.rule_id, f.message);
            }
            println!();
        }
        let clean: Vec<&str> = results
            .iter()
            .filter(|r| r.findings.is_empty())
            .map(|r| r.rel.as_str())
            .collect();
        if !clean.is_empty() {
            println!("clean: {}\n", clean.join(", "));
        }
        if !skipped.is_empty() {
            println!("skipped:");
            for (p, reason) in &skipped {
                println!("  {p} — {reason}");
            }
            println!();
        }
        println!(
            "verdict: {}  (C:{} H:{} M:{} L:{} I:{})  across {} file(s)",
            status, counts.critical, counts.high, counts.medium, counts.low, counts.info, results.len()
        );
    }

    if let Some(threshold) = args.fail_on {
        let threshold: Severity = threshold.into();
        if owned.iter().any(|f| f.severity >= threshold) {
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}

fn print_text(
    args: &ScanArgs,
    pack_id: &str,
    model: &fact_model::FactModel,
    findings: &[engine::Finding],
    verdict: &engine::Verdict,
    digest: &str,
) {
    if !args.quiet {
        println!("sentinel {} — {}", env!("CARGO_PKG_VERSION"), pack_id);
        println!(
            "facts: {} entities, {} relations",
            model.entities.len(),
            model.relations.len()
        );
        if model.entities.is_empty() {
            println!("(nothing to assess)");
        }
        println!();

        if findings.is_empty() {
            println!("No findings.");
        } else {
            println!("Findings ({}):", findings.len());
            for f in findings {
                let loc = match f.lines.as_slice() {
                    [] => String::new(),
                    [l] => format!("  (line {l})"),
                    ls => format!("  (lines {})", ls.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", ")),
                };
                println!("  [{:<8}] {:<34} {}{loc}", f.severity.as_str(), f.rule_id, f.message);
                println!("             fix: {}", f.remediation);
                println!("             {} | {}", f.controls.join(", "), f.evidence.join(", "));
            }
        }
        println!();
    }

    let c = &verdict.counts;
    println!(
        "verdict: {}  (C:{} H:{} M:{} L:{} I:{})",
        verdict.status.as_str().to_uppercase(),
        c.critical,
        c.high,
        c.medium,
        c.low,
        c.info
    );
    println!("digest:  {digest}");
    if !args.quiet && !findings.is_empty() {
        println!("reference: https://github.com/anwen-labs/sentinel/blob/main/RULES.md");
    }
}

fn verify(args: VerifyArgs) -> ExitCode {
    let report_text = match std::fs::read_to_string(&args.report) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", args.report);
            return ExitCode::from(2);
        }
    };
    let report: serde_json::Value = match serde_json::from_str(report_text.trim_start_matches('\u{feff}')) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: invalid report JSON: {e}");
            return ExitCode::from(2);
        }
    };
    let claimed = match report
        .get("envelope")
        .and_then(|e| e.get("report_digest"))
        .and_then(|d| d.as_str())
    {
        Some(s) => s.to_string(),
        None => {
            eprintln!("error: report has no envelope.report_digest");
            return ExitCode::from(2);
        }
    };

    let input = match read_input(&args.compose) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let (model, pack) = match build_model_and_pack(&input, args.r#type, &args.compose, args.strict) {
        Ok(mp) => mp,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let findings = run_pack(pack.as_ref(), &model);
    let verdict = pack.verdict(&findings);
    let core = ReportCore {
        model: &model,
        pack_id: pack.id().to_string(),
        pack_version_hash: pack_version_hash(pack.as_ref()),
        findings: &findings,
        verdict: &verdict,
    };
    let recomputed = core.report_digest();

    if recomputed == claimed {
        println!("verified: report reproduces");
        println!("digest: {recomputed}");
        ExitCode::SUCCESS
    } else {
        eprintln!("MISMATCH — report does not reproduce");
        eprintln!("  claimed:    {claimed}");
        eprintln!("  recomputed: {recomputed}");
        eprintln!("(digests differ if the compose file, engine version, or pack changed)");
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templated_detection_excludes_github_actions_expressions() {
        assert!(looks_templated("name: {{ .Values.x }}")); // Helm
        assert!(looks_templated("a: {{x}}")); // Jinja/Go
        assert!(!looks_templated("run: echo ${{ github.sha }}")); // GHA — allowed
        assert!(!looks_templated("image: nginx:1.25")); // plain
        assert!(!looks_templated("x: ${var}")); // TF-style interpolation
    }

    #[test]
    fn templating_guard_exempts_github_actions_and_explicit_type() {
        // docker/metadata-action uses bare {{ }} tag templates inside a genuine
        // GitHub Actions workflow — must NOT be rejected as a Helm/Go template.
        let gha = "on: push\n\
                   jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n\
                   \x20     - uses: docker/metadata-action@v5\n\
                   \x20       with:\n          tags: type=raw,enable={{is_default_branch}}\n";
        assert!(!rejected_as_templated(InputType::Auto, ".github/workflows/docker.yml", gha));
        // Explicit --type github-actions must bypass the guard too.
        assert!(!rejected_as_templated(InputType::GithubActions, "docker.yml", gha));

        // A real Helm/Go template (auto-detected, non-GHA) is still rejected.
        let helm = "apiVersion: v1\nkind: Service\nmetadata:\n  name: {{ .Values.name }}\n";
        assert!(rejected_as_templated(InputType::Auto, "service.yaml", helm));

        // Explicit --type wins: caller asserts the format; the parser errors if wrong.
        assert!(!rejected_as_templated(InputType::Compose, "chart.yaml", helm));
    }

    #[test]
    fn scannable_candidates_by_name_and_extension() {
        for n in ["Dockerfile", "api.dockerfile", "main.tf", "compose.yml", "deploy.yaml", ".env", ".env.prod"] {
            assert!(is_scannable_candidate(Path::new(n)), "should scan {n}");
        }
        for n in ["README.md", "main.rs", "data.json", "notes.txt", "image.png"] {
            assert!(!is_scannable_candidate(Path::new(n)), "should skip {n}");
        }
    }
}
