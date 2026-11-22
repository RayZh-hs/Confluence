#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use confluence_cli::{NodeConfig, RunningNode, generate_keypair_hex};
use std::{fs, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "confluence",
    about = "Confluence — composable A-to-B connectivity node runner"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a fresh X25519 identity keypair for a Trust Scope or channel.
    Keygen,
    /// Parse and validate a node TOML configuration file without binding sockets.
    Check {
        /// Path to the TOML configuration file.
        config: PathBuf,
    },
    /// Run a Confluence node from a declarative TOML configuration file.
    Run {
        /// Path to the TOML configuration file.
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen => {
            let (secret, public, kid) = generate_keypair_hex();
            println!("secret_key = \"{secret}\"");
            println!("public_key = \"{public}\"");
            println!("scope_kid  = \"{kid}\"");
            ExitCode::SUCCESS
        }
        Commands::Check { config } => match load_config(&config) {
            Ok(cfg) => {
                println!(
                    "OK: validated {} scope(s), {} route(s), {} publish(es), {} bind(s)",
                    cfg.scopes.len(),
                    cfg.routes.len(),
                    cfg.publish_endpoints.len(),
                    cfg.bind_endpoints.len(),
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            }
        },
        Commands::Run { config } => match load_config(&config) {
            Ok(cfg) => match RunningNode::start(cfg).await {
                Ok(running) => {
                    tracing::info!(
                        tcp = ?running.tcp_listener_addrs,
                        udp = ?running.udp_listener_addrs,
                        "confluence node started; press Ctrl-C to stop"
                    );
                    let _ = tokio::signal::ctrl_c().await;
                    tracing::info!("shutting down confluence node");
                    running.shutdown();
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("failed to start node: {err}");
                    ExitCode::FAILURE
                }
            },
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            }
        },
    }
}

fn load_config(path: &PathBuf) -> Result<NodeConfig, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    NodeConfig::from_toml_str(&text)
}
