use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use op_secretd::config;
use op_secretd::doctor::Status;
use op_secretd::error::{Error, Result};
use op_secretd::op::Probe;
use op_secretd::{doctor, lifecycle};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "Secret Service provider backed by 1Password")]
struct Cli {
    /// Path of the configuration file.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon on the session bus.
    Serve,
    /// Check the configuration, 1Password access and the bus.
    Doctor,
    /// Manage the configuration file.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Write a commented configuration file.
    Init {
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn config_path(cli: &Cli) -> Result<PathBuf> {
    match &cli.config {
        Some(path) => Ok(path.clone()),
        None => config::default_path(&env_var),
    }
}

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

fn config_init(path: &std::path::Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(Error::Config(format!(
            "{} already exists; use --force to overwrite",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Config(format!("{}: {e}", parent.display())))?;
    }
    std::fs::write(path, config::EXAMPLE)
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    println!("wrote {}", path.display());
    Ok(())
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let path = config_path(&cli)?;
    match &cli.command {
        Command::Config {
            action: ConfigAction::Init { force },
        } => {
            config_init(&path, *force)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Serve => {
            let config = config::load(&path, &env_var)?;
            init_logging(&config.log_level);
            lifecycle::serve(config, Probe::real()).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Doctor => {
            let config = match config::load(&path, &env_var) {
                Ok(config) => config,
                Err(error) => {
                    println!("FAIL  configuration: {error}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            let checks = doctor::run(&config, &Probe::real()).await;
            for check in &checks {
                let label = match check.status {
                    Status::Ok => "ok  ",
                    Status::Warn => "warn",
                    Status::Fail => "FAIL",
                };
                println!("{label}  {}: {}", check.name, check.detail);
            }
            Ok(if checks.iter().all(|check| check.status != Status::Fail) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("op-secretd: {error}");
            ExitCode::FAILURE
        }
    }
}
