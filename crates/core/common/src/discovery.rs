use mainline::{Dht, Id};
use std::net::SocketAddr;
use crate::oracle::Oracle;

pub struct ParasiticDiscovery {
    dht: Dht,
}

impl ParasiticDiscovery {
    pub fn new() -> Self {
        Self { dht: Dht::default() }
    }

    /// Unified Discovery Cycle: Generate InfoHash, Announce (Optional), Find Peers
    pub async fn run_cycle(&self, announce_port: Option<u16>) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
        // 1. Get Financial InfoHash
        let info_hash = Oracle::generate_financial_hash().await?;
        let info_hash_id = Id::from_bytes(&info_hash).unwrap();

        // 2. Announce Self if requested (Mesh Role)
        if let Some(port) = announce_port {
             self.dht.announce_peer(info_hash_id, Some(port))
                 .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())) as Box<dyn std::error::Error + Send + Sync>)?;
             // println!("* [Common] Announced on Port: {}", port);
        }

        // 3. Find Peers (Seeker & Mesh Role)
        let mut peers = Vec::new();
        let response = self.dht.get_peers(info_hash_id);
        
        for peer in response.closest_nodes {
             peers.push(peer.address);
        }
        
        Ok(peers)
    }
}
