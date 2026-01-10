use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, WebSocketStream, MaybeTlsStream};
use tokio_tungstenite::tungstenite::protocol::Message;
use protocol::{GhostPacket, CommandType, CommandPayload, MeshMsg, PeerInfo, Registration, GossipMsg};
use serde_json::json;
use crate::crypto::{sign_command, create_payload};
use ed25519_dalek::SigningKey;
use url::Url;
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncWrite};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

// Ghost P2P Client (Transient Connection)
// Ghost connects, drops payload, disconnects.
// Refactored to use direct WebSocket connections (QUIC transport is handled at node level)
pub struct GhostClient<S> {
    ws_stream: WebSocketStream<S>, 
}

impl GhostClient<MaybeTlsStream<TcpStream>> {
    pub async fn connect(url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let (ws_stream, _) = connect_async(url).await?;
        Ok(GhostClient { ws_stream })
    }
    
    /// Connect directly to a peer address (IP:Port) via WebSocket
    pub async fn connect_direct(peer_address: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let url = format!("ws://{}/ws", peer_address);
        Self::connect(&url).await
    }
}

// Common methods for any valid Stream
impl<S> GhostClient<S> 
where S: AsyncRead + AsyncWrite + Unpin 
{
    pub async fn handshake(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
         let mut rng = OsRng;
         let my_secret = EphemeralSecret::random_from_rng(&mut rng);
         let my_public = PublicKey::from(&my_secret);
         
         let msg = MeshMsg::ClientHello { 
             ephemeral_pub: hex::encode(my_public.as_bytes()) 
         };
         self.ws_stream.send(Message::Text(serde_json::to_string(&msg)?.into())).await?;
         
         // Wait for ServerHello
         while let Some(res) = self.ws_stream.next().await {
            if let Ok(Message::Text(txt)) = res {
                 if let Ok(MeshMsg::ServerHello { ephemeral_pub }) = serde_json::from_str::<MeshMsg>(&txt) {
                     let server_pub_bytes = hex::decode(ephemeral_pub)?;
                     let server_pub_arr: [u8; 32] = server_pub_bytes.try_into().map_err(|_| "Invalid Key Length")?;
                     let server_public = PublicKey::from(server_pub_arr);
                     let shared_secret = my_secret.diffie_hellman(&server_public);
                     return Ok(shared_secret.as_bytes().to_vec());
                 }
            }
         }
         Err("Handshake Timeout/Failure".into())
    }

    pub async fn register(&mut self, pub_hex: &str) -> Result<(), Box<dyn std::error::Error>> {
        // PoW Solver
        use sha2::{Sha256, Digest};
        let mut pow_nonce: u64 = 0;
        let start = std::time::Instant::now();
        println!("Ghost Solving PoW...");
        loop {
            let input = format!("{}{}", pub_hex, pow_nonce);
            let hash = Sha256::digest(input.as_bytes());
            if hash[0] == 0 && hash[1] == 0 {
                break;
            }
            pow_nonce += 1;
        }
        println!("PoW Solved in {:?}", start.elapsed());

        let reg = Registration {
            pub_key: pub_hex.to_string(),
            peer_address: "ghost_transient".to_string(),
            signature: "sig".to_string(),
            pow_nonce,
            timestamp: chrono::Utc::now().timestamp(),
        };
        let msg = MeshMsg::Register(reg);
        self.ws_stream.send(Message::Text(serde_json::to_string(&msg)?.into())).await?;
        Ok(())
    }

    pub async fn get_peers(&mut self) -> Result<Vec<PeerInfo>, Box<dyn std::error::Error>> {
        let msg = MeshMsg::GetPeers;
        self.ws_stream.send(Message::Text(serde_json::to_string(&msg)?.into())).await?;
        
        while let Some(res) = self.ws_stream.next().await {
            if let Ok(Message::Text(txt)) = res {
                if let Ok(MeshMsg::Peers(list)) = serde_json::from_str::<MeshMsg>(&txt) {
                    return Ok(list);
                }
            }
        }
        Ok(vec![])
    }
    
    // Inject Gossip into a connected Node
    pub async fn inject_command(&mut self, payload: CommandPayload, sign_key: &SigningKey, session_key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        // Encrypt Payload (Ghost -> Mesh)
        let json_payload = serde_json::to_string(&payload)?;

        // Encrypt (ChaCha20Poly1305) using Session Key
        use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, AeadCore};
        use chacha20poly1305::aead::Aead;
        
        let mut key_bytes = [0u8; 32];
        if session_key.len() == 32 {
            key_bytes.copy_from_slice(session_key);
        } else {
             return Err("Invalid Session Key length".into());
        }
        let cipher = ChaCha20Poly1305::new(&Key::from(key_bytes));
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, json_payload.as_bytes()).map_err(|_| "Encryption Failed")?;
        
        // Create Packet (Signed)
        use protocol::CommandType;
        let mut packet = GhostPacket::new(CommandType::StartModule, ciphertext, sign_key);
        
        // Prepend Nonce to ciphertext in `data`
        let mut final_data = nonce.to_vec();
        final_data.extend(packet.data); 
        packet.data = final_data;
        
        // Wrap in GossipMsg
        let gossip = GossipMsg {
            id: payload.id.clone(),
            packet,
            ttl: 5, // 5 hops
        };
        
        let msg = MeshMsg::Gossip(gossip);
        self.ws_stream.send(Message::Text(serde_json::to_string(&msg)?.into())).await?;
        
        Ok(())
    }
}
