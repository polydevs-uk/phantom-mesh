use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Discovery source for a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    Lan,    // Local mDNS Discovery
    Dht,    // BitTorrent DHT
    Signal, // Received via Gossipsub Signaling
}

/// Connection state machine for a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Just discovered, not yet attempted
    Unknown,
    /// Connection attempt in progress (SDP sent)
    Pending,
    /// ICE negotiation in progress
    IceCheck,
    /// Successfully connected
    Connected,
    /// Connection failed (temporary, will retry)
    Failed,
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerState::Unknown => write!(f, "Unknown"),
            PeerState::Pending => write!(f, "Pending"),
            PeerState::IceCheck => write!(f, "IceCheck"),
            PeerState::Connected => write!(f, "Connected"),
            PeerState::Failed => write!(f, "Failed"),
        }
    }
}

/// Entry for a single peer in the registry
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// Unique peer identifier (libp2p PeerID or generated hash)
    pub peer_id: String,
    /// LAN IP address (from Local mDNS)
    pub lan_addr: Option<SocketAddr>,
    /// Public IP address (from DHT)
    pub public_addr: Option<SocketAddr>,
    /// Current connection state
    pub state: PeerState,
    /// Last state transition time
    pub last_seen: Instant,
    /// Number of failed connection attempts
    pub retry_count: u8,
    /// Discovery source that first found this peer
    pub first_source: DiscoverySource,
}

impl PeerEntry {
    pub fn new(peer_id: String, source: DiscoverySource, addr: SocketAddr) -> Self {
        let (lan_addr, public_addr) = match source {
            DiscoverySource::Lan => (Some(addr), None),
            DiscoverySource::Dht | DiscoverySource::Signal => (None, Some(addr)),
        };
        
        Self {
            peer_id,
            lan_addr,
            public_addr,
            state: PeerState::Unknown,
            last_seen: Instant::now(),
            retry_count: 0,
            first_source: source,
        }
    }
    
    /// Get preferred address (LAN has priority over Public)
    pub fn preferred_addr(&self) -> Option<SocketAddr> {
        self.lan_addr.or(self.public_addr)
    }
    
    /// Check if entry has expired (5 minutes without update)
    pub fn is_expired(&self) -> bool {
        self.last_seen.elapsed() > Duration::from_secs(300)
    }
}

/// Unified Peer Registry with State Machine
pub struct PeerRegistry {
    peers: HashMap<String, PeerEntry>,
    /// Max retry attempts before giving up
    max_retries: u8,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            max_retries: 3,
        }
    }
    
    /// Register a peer from a discovery source.
    /// Returns `true` if this is a NEW peer that should be connected.
    /// Returns `false` if peer already exists or is already connected.
    pub fn register(&mut self, peer_id: &str, source: DiscoverySource, addr: SocketAddr) -> bool {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            // Peer already exists - update address if new source
            match source {
                DiscoverySource::Lan => {
                    if entry.lan_addr.is_none() {
                        println!("[Registry] Updated peer {} with LAN addr: {}", peer_id, addr);
                        entry.lan_addr = Some(addr);
                    }
                },
                DiscoverySource::Dht | DiscoverySource::Signal => {
                    if entry.public_addr.is_none() {
                        entry.public_addr = Some(addr);
                    }
                }
            }
            entry.last_seen = Instant::now();
            
            // Don't connect again if already pending/connected
            false
        } else {
            // New peer - register it
            println!("[Registry] New peer registered: {} via {:?} at {}", peer_id, source, addr);
            let entry = PeerEntry::new(peer_id.to_string(), source, addr);
            self.peers.insert(peer_id.to_string(), entry);
            true
        }
    }
    
    /// Check if we should attempt to connect to this peer
    pub fn should_connect(&self, peer_id: &str) -> bool {
        match self.peers.get(peer_id) {
            None => true, // Unknown peer, allow connection
            Some(entry) => {
                match entry.state {
                    PeerState::Unknown => true,
                    PeerState::Failed if entry.retry_count < self.max_retries => true,
                    PeerState::Pending | PeerState::IceCheck | PeerState::Connected => {
                        println!("[Registry] Peer {} already in state {}, skipping.", peer_id, entry.state);
                        false
                    },
                    PeerState::Failed => {
                        println!("[Registry] Peer {} exceeded max retries ({}), skipping.", peer_id, self.max_retries);
                        false
                    }
                }
            }
        }
    }
    
    /// Update peer connection state
    pub fn update_state(&mut self, peer_id: &str, new_state: PeerState) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            let old_state = entry.state;
            entry.state = new_state;
            entry.last_seen = Instant::now();
            
            // Track retries
            if new_state == PeerState::Failed {
                entry.retry_count += 1;
            } else if new_state == PeerState::Connected {
                entry.retry_count = 0; // Reset on success
            }
            
            println!("[Registry] Peer {} state: {} -> {}", peer_id, old_state, new_state);
        }
    }
    
    /// Get preferred address for a peer (LAN priority)
    pub fn get_preferred_addr(&self, peer_id: &str) -> Option<SocketAddr> {
        self.peers.get(peer_id).and_then(|e| e.preferred_addr())
    }
    
    /// Get peer entry by ID
    pub fn get(&self, peer_id: &str) -> Option<&PeerEntry> {
        self.peers.get(peer_id)
    }
    
    /// Get number of connected peers
    pub fn connected_count(&self) -> usize {
        self.peers.values().filter(|e| e.state == PeerState::Connected).count()
    }
    
    /// Clean up expired entries
    pub fn cleanup_expired(&mut self) {
        let before = self.peers.len();
        self.peers.retain(|_, e| !e.is_expired() || e.state == PeerState::Connected);
        let after = self.peers.len();
        if before != after {
            println!("[Registry] Cleaned up {} expired entries.", before - after);
        }
    }
    
    /// Get all peer IDs
    pub fn all_peer_ids(&self) -> Vec<String> {
        self.peers.keys().cloned().collect()
    }
}

/// Thread-safe wrapper for PeerRegistry
pub type SharedPeerRegistry = Arc<RwLock<PeerRegistry>>;

/// Create a new shared registry
pub fn new_shared_registry() -> SharedPeerRegistry {
    Arc::new(RwLock::new(PeerRegistry::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port)
    }
    
    #[test]
    fn test_register_new_peer() {
        let mut registry = PeerRegistry::new();
        assert!(registry.register("peer1", DiscoverySource::Lan, addr(443)));
        assert!(!registry.register("peer1", DiscoverySource::Dht, addr(443))); // Duplicate
    }
    
    #[test]
    fn test_should_connect_state_machine() {
        let mut registry = PeerRegistry::new();
        registry.register("peer1", DiscoverySource::Lan, addr(443));
        
        assert!(registry.should_connect("peer1")); // Unknown state
        
        registry.update_state("peer1", PeerState::Pending);
        assert!(!registry.should_connect("peer1")); // Pending - skip
        
        registry.update_state("peer1", PeerState::Connected);
        assert!(!registry.should_connect("peer1")); // Connected - skip
    }
    
    #[test]
    fn test_retry_logic() {
        let mut registry = PeerRegistry::new();
        registry.register("peer1", DiscoverySource::Lan, addr(443));
        
        // Fail 3 times
        for i in 0..3 {
            registry.update_state("peer1", PeerState::Failed);
            if i < 2 {
                assert!(registry.should_connect("peer1")); // Retries allowed
            } else {
                assert!(!registry.should_connect("peer1")); // Max retries exceeded
            }
        }
    }
}
