pub const INSTALL_DIR_NAME: &str = ".phantom_node";

// Bootstrap Peers
pub const BOOTSTRAP_PEERS: [&str; 3] = [
    "127.0.0.1:9000",
    "0.0.0.0:9001",    // Placeholder
    "0.0.0.0:9002"     // Placeholder
];

// Legacy alias for compatibility
pub const BOOTSTRAP_ONIONS: [&str; 3] = BOOTSTRAP_PEERS;

// Pre-Shared Swarm Key (32 bytes)
pub const SWARM_KEY: &[u8; 32] = b"PhantomMeshV3_SecretSwarmKey_32b";
