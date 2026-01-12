use crate::network::GhostClient;
use crate::discovery::ParasiticDiscovery;
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use common::time::TimeKeeper;

// --- Interactive Commands ---

pub async fn handle_ping(client: &mut GhostClient, local_peers: Arc<Mutex<HashSet<String>>>) {
    println!("[*] Pinging Mesh Network...");
    
    // 1. Discover Peers
    // a. DHT
    let mut targets = resolve_targets(None).await;
    
    // b. Local Discovery
    {
        let local = local_peers.lock().unwrap();
        if !local.is_empty() {
             println!("[*] Incorporating {} Local LAN Peers...", local.len());
             for peer_addr in local.iter() {
                 targets.push(peer_addr.clone());
             }
        }
    }
    
    // Dedup
    targets.sort();
    targets.dedup();

    if targets.is_empty() {
        eprintln!("[-] No peers found to ping.");
        return;
    }
    
    println!("[*] Found {} unique potential peers. Verifying connectivity...", targets.len());
    
    // 2. Dial Each (Active Ping)
    let mut success = 0;
    for target in &targets {
        // Simple visual indicator
        use std::io::{self, Write};
        print!("  > Pinging {} ... ", target);
        io::stdout().flush().unwrap();
        
        match client.dial(target).await {
            Ok(_) => {
                println!("Pong! (Alive)");
                success += 1;
            },
            Err(e) => {
                // Shorten error for UI cleanliness
                println!("Unreachable"); // ({})", e);
            }
        }
    }
    
    println!("[*] Ping Complete. {}/{} nodes active.", success, targets.len());
}


pub async fn handle_scan() {
    println!("[Scan] Initiating TOTP-DGA Scan...");
    
    // 1. Sync Time
    println!("[Scan] Synchronizing Time via NTP...");
    TimeKeeper::init().await;
    let synced_time = TimeKeeper::get_synced_time_secs();
    println!("[Scan] Synced Time: {}", synced_time);
    
    // 2. Run Discovery
    let discovery = ParasiticDiscovery::new();
    println!("[Scan] Running Discovery Cycle...");
    match discovery.run_cycle(None, synced_time).await {
        Ok(peers) => {
            println!("[Scan] SUCCESS: Discovered {} Mesh Nodes.", peers.len());
            for (i, p) in peers.iter().enumerate() {
                println!("  {}. {:?}", i+1, p);
            }
        },
        Err(e) => eprintln!("[Scan] FAILED: {}", e),
    }
}

// --- Helpers ---

async fn resolve_targets(bootstrap: Option<String>) -> Vec<String> {
    if let Some(b) = bootstrap {
        return vec![b];
    }
    
    println!("[Ghost] Scanning DHT for targets...");
    
    // Sync Time
    let synced_time = TimeKeeper::get_synced_time_secs();
    println!("[Ghost] Using Synced Time: {}", synced_time);
    
    let discovery = ParasiticDiscovery::new();
    match discovery.run_cycle(None, synced_time).await {
        Ok(addrs) => {
            println!("[Ghost] Discovered {} nodes via DHT.", addrs.len());
            let list: Vec<String> = addrs.iter()
                .map(|addr| format!("/ip4/{}/tcp/{}", addr.ip(), addr.port()))
                .collect();
            list
        },
        Err(e) => {
            eprintln!("[Ghost] DHT Discovery Failed: {}", e);
            vec![]
        }
    }
}

// --- Deprecated / Hidden Commands ---

/*
pub async fn handle_keygen(output: PathBuf) {
    if let Some(parent) = output.parent() {
        if !parent.exists() {
             let _ = std::fs::create_dir_all(parent);
        }
    }
    let pub_key = crypto::generate_key(&output);
    println!("Generated Key at: {}", output.display());
    println!("Public Key: {}", pub_key);
}

pub async fn handle_list(bootstrap: Option<String>) {
    // ...
}

pub async fn handle_target(...) { ... }
pub async fn handle_broadcast(...) { ... }
pub async fn handle_load_module(...) { ... }
pub async fn handle_start_module(...) { ... }
*/
