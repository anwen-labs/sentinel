//! `sentinel` — deterministic Docker Compose security scanner.
//!
//!   sentinel scan compose.yml
//!   cat compose.yml | sentinel scan -
//!   sentinel scan compose.yml --format json
//!   sentinel scan compose.yml --fail-on high     # exit 1 if any High/Critical

use std::io::Read;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use compose_parser::try_parse;
use engine::{full_report_json, pack_version_hash, run_pack, Pack, ReportCore, Severity};
use pack_sentinel_core::SentinelCorePack;

#[derive(Parser)]
#[command(
    name = "sentinel",
    version,
    about = "Deterministic Docker Compose security scanner"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a Docker Compose file for security misconfigurations.
    Scan(ScanArgs),
}

#[derive(Args)]
struct ScanArgs {
    /// Path to a compose file, or "-" to read from stdin.
    path: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Exit non-zero if any finding is at or above this severity (for CI).
    #[arg(long, value_name = "SEVERITY")]
    fail_on: Option<SeverityArg>,

    /// Only print the verdict line and digest.
    #[arg(long)]
    quiet: bool,
}

#[derive(Clone, ValueEnum)]
enum Format {
    Text,
    Json,
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
    }
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

fn scan(args: ScanArgs) -> ExitCode {
    let input = match read_input(&args.path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let model = match try_parse(&input) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
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
        Format::Text => print_text(&args, &model, &findings, &verdict, &digest),
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

fn print_text(
    args: &ScanArgs,
    model: &fact_model::FactModel,
    findings: &[engine::Finding],
    verdict: &engine::Verdict,
    digest: &str,
) {
    if !args.quiet {
        println!("sentinel {} — sentinel-core", env!("CARGO_PKG_VERSION"));
        println!(
            "facts: {} entities, {} relations",
            model.entities.len(),
            model.relations.len()
        );
        if model.entities.is_empty() {
            println!("(no services found — nothing to assess)");
        }
        println!();

        if findings.is_empty() {
            println!("No findings.");
        } else {
            println!("Findings ({}):", findings.len());
            for f in findings {
                println!("  [{:<8}] {:<34} {}", f.severity.as_str(), f.rule_id, f.message);
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
}
