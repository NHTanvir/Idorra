//! `idorra` CLI — thin front-end over `idorra-core`. All safety rails (scope,
//! rate limiting, dry-run, redaction) live in the core; this binary only parses
//! arguments, wires the engine, and renders output.

mod cli;
mod init;
mod render;

use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;

use cli::{Cli, Command, RunArgs};
use idorra_core::config::Config;
use idorra_core::engine::Engine;
use idorra_core::logging::{AuditSink, FileAuditLog, NullAuditLog};
use idorra_core::report;

#[tokio::main]
async fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();

    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => init::scaffold(&args.dir),
        Command::Plan(args) => cmd_plan(args).await,
        Command::Run(args) => cmd_run(args).await,
    }
}

fn load_config(args: &RunArgs) -> Result<Config> {
    let secrets = args.secrets.exists().then_some(args.secrets.as_path());
    Config::load(&args.config, secrets)
        .with_context(|| format!("loading config {:?}", args.config))
}

async fn cmd_plan(args: RunArgs) -> Result<()> {
    let config = load_config(&args)?;
    let engine = Engine::from_config(config, Arc::new(NullAuditLog), false, Some(true))?;
    let plan = engine.plan()?;

    println!("Generated {} test cases.\n", plan.len());

    use std::collections::BTreeMap;
    let mut by_strategy: BTreeMap<String, usize> = BTreeMap::new();
    for c in &plan {
        *by_strategy.entry(format!("{:?}", c.strategy)).or_default() += 1;
    }
    println!("By strategy:");
    for (k, v) in &by_strategy {
        println!("  {k}: {v}");
    }

    println!("\nFirst cases:");
    for c in plan.iter().take(8) {
        println!(
            "  [{:?}] {} {} (session {}, id {}, in {})",
            c.strategy, c.method, c.path_template, c.session, c.id_value, c.param_location
        );
    }
    Ok(())
}

async fn cmd_run(args: RunArgs) -> Result<()> {
    let dry_override = args.dry_run_override().map_err(|e| anyhow::anyhow!(e))?;
    let config = load_config(&args)?;

    let run_id = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let report_dir = config.general.report_dir.clone();
    let log_path = config.general.log_dir.join(format!("idorra-{run_id}.jsonl"));

    let audit: Arc<dyn AuditSink> = match FileAuditLog::create(&log_path) {
        Ok(f) => Arc::new(f),
        Err(e) => {
            eprintln!(
                "warning: could not open audit log {log_path:?}: {e}; continuing without file audit"
            );
            Arc::new(NullAuditLog)
        }
    };

    let engine = Engine::from_config(config, audit, args.include_secrets_in_log, dry_override)?;
    render::print_run_header(&engine);

    if !engine.is_dry_run() && !args.yes && !confirm_live()? {
        bail!("aborted: refusing to run live without confirmation (use --yes for non-interactive runs)");
    }
    if args.include_secrets_in_log {
        eprintln!(
            "warning: --include-secrets-in-log is ON — tokens/cookies will appear UNREDACTED in \
             the logs and reports."
        );
    }

    let summary = engine.run().await?;
    render::print_summary(&summary);

    let paths = report::write_reports(&summary, &report_dir, &run_id)?;
    println!("\nReports written:");
    println!("  json     : {}", paths.json.display());
    println!("  markdown : {}", paths.markdown.display());
    println!("  audit log: {}", log_path.display());
    Ok(())
}

/// Ask for explicit confirmation before a live run. Returns false when stdin is
/// not a terminal (so non-interactive live runs must pass `--yes`).
fn confirm_live() -> Result<bool> {
    use std::io::{BufRead, Write};
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    print!("Proceed with LIVE requests to the scope above? [y/N]: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}
