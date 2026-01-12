use protocol::CommandPacket;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use std::convert::TryInto;
use crate::p2p::webrtc::WebRtcManager;

// Hardcoded Phantom Key (Admin Public Key)
const PHANTOM_PUBLIC_KEY_BYTES: [u8; 32] = [
    0x75, 0xbf, 0x34, 0x60, 0xf7, 0x00, 0x57, 0x06, 
    0xa3, 0x82, 0x85, 0x4d, 0x0b, 0x31, 0xc7, 0x63, 
    0x30, 0x4d, 0x15, 0x19, 0x18, 0xd1, 0xca, 0x87, 
    0xe7, 0x38, 0x99, 0xcc, 0x79, 0x3d, 0xb8, 0x6a
];

pub struct FloodingManager {
    seen_cache: Arc<Mutex<HashSet<u64>>>,
    webrtc: Arc<WebRtcManager>,
}

impl FloodingManager {
    pub fn new(webrtc: Arc<WebRtcManager>) -> Self {
        Self {
            seen_cache: Arc::new(Mutex::new(HashSet::new())),
            webrtc,
        }
    }

    /// Process incoming command from a peer
    pub async fn handle_incoming_command(&self, packet: CommandPacket, sender_id: Option<String>) {
        let sender = sender_id.unwrap_or_else(|| "Unknown".to_string());
        
        // 1. Deduplicate
        let packet_id = Self::compute_packet_id(&packet);
        {
            let mut cache = self.seen_cache.lock().unwrap();
            if cache.contains(&packet_id) {
                println!("[Flooding] Duplicate command from {}, ignoring.", sender);
                return;
            }
            cache.insert(packet_id);
            
            // Limit cache size (simple eviction)
            if cache.len() > 10000 {
                cache.clear();
            }
        }
        
        println!("[Flooding] New command (ID: {}) from {}", packet_id, sender);
        
        // 2. Verify Signature
        if !self.verify_signature(&packet) {
            println!("[Flooding] Invalid signature from {}. Dropping.", sender);
            return;
        }
        println!("[Flooding] Signature verified from {}.", sender);
        
        // 3. Execute Command
        self.execute_command(&packet);
        
        // 4. Rebroadcast to peers
        println!("[Flooding] Rebroadcasting command to mesh...");
        if let Ok(data) = bincode::serialize(&packet) {
             self.webrtc.broadcast_data(data).await;
        }
    }
    
    fn compute_packet_id(packet: &CommandPacket) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        packet.id.hash(&mut hasher);
        packet.type_.hash(&mut hasher);
        // Also hash payload for uniqueness
        packet.payload.hash(&mut hasher);
        hasher.finish()
    }
    
    fn verify_signature(&self, packet: &CommandPacket) -> bool {
        if packet.signature.len() != 64 { 
            return false; 
        }
        
        let vk_bytes = PHANTOM_PUBLIC_KEY_BYTES;
        if let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) {
             let mut signature_bytes = [0u8; 64];
             signature_bytes.copy_from_slice(&packet.signature);
             let signature = Signature::from_bytes(&signature_bytes);
             
             // Verify manually since CommandPacket doesn't have a verify method
             let mut temp = packet.clone();
             temp.signature = Vec::new();
             if let Ok(msg) = bincode::serialize(&temp) {
                 return vk.verify(&msg, &signature).is_ok();
             }
             return false;
        }

        false
    }
    
    fn execute_command(&self, packet: &CommandPacket) {
        println!("[Execute] Type={}, Payload={} bytes", packet.type_, packet.payload.len());
        
        match packet.type_ {
            0 => {
                println!("[Execute] PING received. Mesh is alive!");
                // In future: Send PONG back
            },
            1 => {
                println!("[Execute] UPDATE command (Not implemented)");
            },
            _ => {
                println!("[Execute] Unknown command type: {}", packet.type_);
            }
        }
    }
}
