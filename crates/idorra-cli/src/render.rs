//! Terminal rendering of run info and findings (plain text, no color deps).

use idorra_core::engine::RunSummary;
use idorra_core::Engine;

/// Print the pre-run banner: mode, scope, and pacing — a last sanity check.
pub fn print_run_header(engine: &Engine) {
    let cfg = engine.config();
    let mode = if engine.is_dry_run() { "DRY-RUN (nothing will be sent)" } else { "LIVE" };
    println!("idorra run — mode: {mode}");
    println!("  scope.allow : {}", cfg.scope.allow.join(", "));
    if !cfg.scope.allow_ports.is_empty() {
        let ports: Vec<String> = cfg.scope.allow_ports.iter().map(|p| p.to_string()).collect();
        println!("  scope.ports : {}", ports.join(", "));
    }
    println!(
        "  pacing      : {} req/s, burst {}, max {} in-flight",
        cfg.rate_limit.requests_per_second,
        cfg.rate_limit.burst,
        cfg.rate_limit.max_concurrency
    );
    println!();
}

/// Print the post-run summary and findings.
pub fn print_summary(summary: &RunSummary) {
    println!("\n── Run summary ──");
    println!("  planned : {}", summary.total);
    println!("  sent    : {}", summary.sent);
    println!("  blocked : {}", summary.blocked);
    println!("  dry-run : {}", summary.dry_run);
    println!("  errored : {}", summary.errored);
    println!("  findings: {}", summary.findings.len());

    if summary.findings.is_empty() {
        println!("\nNo findings flagged.");
        return;
    }

    println!("\n── Findings (most severe first) ──");
    for (i, f) in summary.findings.iter().enumerate() {
        println!(
            "  {}. [{} / {} conf] {}",
            i + 1,
            f.severity,
            f.confidence,
            f.summary
        );
        if !f.involved_sessions.is_empty() {
            println!("      sessions: {}", f.involved_sessions.join(", "));
        }
    }
}
