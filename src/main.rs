use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use op_secretd::config;
use op_secretd::error::Result;
use op_secretd::lifecycle;
use op_secretd::op::Probe;
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
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let path = match &cli.config {
        Some(path) => path.clone(),
        None => config::default_path(&env_var)?,
    };
    match cli.command {
        Command::Serve => {
            let config = config::load(&path, &env_var)?;
            init_logging(&config.log_level);
            lifecycle::serve(config, Probe::real()).await?;
            Ok(ExitCode::SUCCESS)
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
