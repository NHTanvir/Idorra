//! Command-line surface (clap).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Authorized IDOR / access-control testing tool.
#[derive(Debug, Parser)]
#[command(name = "idorra", version, about, long_about = None)]
pub struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scaffold a starter `idorra.toml` + gitignored `secrets.toml`.
    Init(InitArgs),
    /// Print the generated test plan without sending anything.
    Plan(RunArgs),
    /// Run the configured tests (dry-run by default; pass `--live` to send).
    Run(RunArgs),
}

/// Shared config-location + mode flags for `run`/`plan`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Path to the main config file.
    #[arg(short, long, default_value = "idorra.toml")]
    pub config: PathBuf,

    /// Path to the secrets file (sessions/tokens).
    #[arg(short, long, default_value = "secrets.toml")]
    pub secrets: PathBuf,

    /// Actually send requests (overrides `general.dry_run`).
    #[arg(long)]
    pub live: bool,

    /// Force dry-run (overrides `general.dry_run`).
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Do NOT redact Authorization/Cookie values in logs and reports.
    #[arg(long)]
    pub include_secrets_in_log: bool,

    /// Skip the interactive confirmation before a live run.
    #[arg(long)]
    pub yes: bool,
}

/// `init` arguments.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Directory to scaffold into.
    #[arg(default_value = ".")]
    pub dir: PathBuf,
}

impl RunArgs {
    /// Resolve the dry-run override from `--live` / `--dry-run`.
    ///
    /// `None` means "use the config default". Returns an error if both flags are
    /// passed.
    pub fn dry_run_override(&self) -> Result<Option<bool>, String> {
        match (self.live, self.dry_run) {
            (true, true) => Err("--live and --dry-run are mutually exclusive".into()),
            (true, false) => Ok(Some(false)),
            (false, true) => Ok(Some(true)),
            (false, false) => Ok(None),
        }
    }
}
