#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use confluence_cli::{NodeConfig, RunningNode};
use confluence_core::StaticKeypair;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(
    name = "confluence",
    version,
    about = "Confluence cleanroom A-to-B connectivity node runner and key utility"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh X25519 static keypair (prints secret key, PeerId, and TargetTag)
    Keygen {
        /// Output in TOML key/value format
        #[arg(long)]
        toml: bool,
    },
    /// Derive the public PeerId and 8-byte TargetTag from a 32-byte hex secret key
    Pubkey {
        /// 64-character hex secret key
        #[arg(short, long)]
        secret: String,
    },
    /// Parse and validate a declarative node TOML configuration without binding sockets
    Validate {
        /// Path to the node TOML configuration file
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Run a Confluence Node from a declarative TOML configuration until interrupted
    Run {
        /// Path to the node TOML configuration file
        #[arg(short, long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { toml } => {
            let kp = StaticKeypair::generate();
            let secret_hex = hex::encode(kp.secret_bytes());
            if toml {
                println!("secret_key = \"{secret_hex}\"");
                println!("public_key = \"{}\"", kp.peer_id());
                println!("target_tag = \"{}\"", kp.target_tag());
            } else {
                println!("Secret Key: {secret_hex}");
                println!("Public Key (PeerId): {}", kp.peer_id());
                println!("Target Tag: {}", kp.target_tag());
            }
        }
        Command::Pubkey { secret } => {
            let kp = StaticKeypair::from_secret_hex(&secret)?;
            println!("Public Key (PeerId): {}", kp.peer_id());
            println!("Target Tag: {}", kp.target_tag());
        }
        Command::Validate { config } => {
            let raw = std::fs::read_to_string(&config)?;
            let parsed = NodeConfig::from_toml_str(&raw)?;
            println!(
                "Configuration '{}' is valid ({} scope(s), {} route(s)).",
                config.display(),
                parsed.scopes.len(),
                parsed.routes.len()
            );
        }
        Command::Run { config } => {
            let raw = std::fs::read_to_string(&config)?;
            let parsed = NodeConfig::from_toml_str(&raw)?;
            let running = RunningNode::start(parsed).await?;
            info!(path = %config.display(), "Confluence node started; press Ctrl+C to stop");
            tokio::signal::ctrl_c().await?;
            info!("Shutting down Confluence node...");
            running.shutdown().await;
        }
    }
    Ok(())
}
