use mainline::{Dht, Id};
use std::net::SocketAddr;
use crate::oracle::Oracle;

pub mod local;

pub struct ParasiticDiscovery {
    dht: Dht,
}

impl ParasiticDiscovery {
    pub fn new() -> Self {
        Self { dht: Dht::default() }
    }

    /// Discovery Cycle using NTP-synced time. Only uses CURRENT InfoHash.
    pub async fn run_cycle(&self, announce_port: Option<u16>, synced_time_secs: u64) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
        // 1. Get the SINGLE Active InfoHash (TOTP Time-based)
        let hash_bytes = Oracle::get_current_infohash(synced_time_secs);
        let info_hash_id = Id::from_bytes(&hash_bytes).unwrap();
        let info_hash_hex = hex::encode(hash_bytes);
        
        println!("[Discovery] TOTP-DGA InfoHash [Current]: {}", info_hash_hex);
        
        // 2. Announce Self if requested (Mesh Role)
        if let Some(port) = announce_port {
             println!("[Discovery] Announcing to BitTorrent DHT (InfoHash: {})...", info_hash_hex);
             match self.dht.announce_peer(info_hash_id, Some(port)) {
                 Ok(_) => println!("[Discovery] Announce Success."),
                 Err(e) => println!("[Discovery] Announce Failed: {:?}", e),
             }
        }

        // 3. Find Peers (wait a moment for DHT propagation then query)
        println!("[Discovery] Querying BitTorrent DHT for Peers...");
        let mut response = self.dht.get_peers(info_hash_id);
        
        // Collect ACTUAL announced peers (not just routing nodes)
        let mut all_peers = Vec::new();
        
        // Method 1: Iterate the peers iterator (these are actual announced peers)
        let mut peer_count = 0;
        for peer_response in &mut response {
            peer_count += 1;
            // GetPeerResponse has `from` and `peer` fields
            all_peers.push(peer_response.peer);
        }
        
        println!("[Discovery] BitTorrent Response: Found {} announced peers.", peer_count);
        
        // Dedup
        all_peers.sort();
        all_peers.dedup();
        
        Ok(all_peers)
    }
}
