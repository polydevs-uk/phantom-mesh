use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use hex;

// Configuration: 4 hours
const SLOT_DURATION: u64 = 4 * 3600;

pub struct Oracle;

impl Oracle {
    /// Returns the SINGLE active InfoHash based on synced time.
    /// `synced_time_secs` should be obtained via NTP or HTTP Date header.
    pub fn get_current_infohash(synced_time_secs: u64) -> [u8; 20] {
        // Time-based Slot (4 Hours)
        let current_slot = synced_time_secs / SLOT_DURATION;
        Self::generate_hash(current_slot)
    }
    
    /// Legacy: Get current using system time (use only if NTP sync failed)
    pub fn get_current_infohash_local() -> [u8; 20] {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self::get_current_infohash(current_time)
    }

    /// Core Hash Generation
    fn generate_hash(slot: u64) -> [u8; 20] {
        let seed = Self::get_seed_obfuscated();
        let raw_input = format!("{}{}", seed, slot);
        
        // SHA256 as requested
        let mut hasher = Sha256::new();
        hasher.update(raw_input.as_bytes());
        let result = hasher.finalize(); // 32 bytes
        
        // Truncate to 20 bytes for Mainline DHT compatibility (160-bit)
        let mut truncated = [0u8; 20];
        truncated.copy_from_slice(&result[0..20]);
        truncated
    }
    
    /// Obfuscated Seed Retrieval (Runtime Reconstruction)
    fn get_seed_obfuscated() -> String {
        // Obfuscation to evade static string analysis
        let part1 = "Phantom_Protocol";
        let part2 = "_v3_Eternal_Seed";
        let part3 = "_99281";
        format!("{}{}{}", part1, part2, part3)
    }
}
