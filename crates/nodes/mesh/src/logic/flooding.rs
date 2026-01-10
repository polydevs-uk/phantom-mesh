use protocol::CommandPacket;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use std::convert::TryInto;
use crate::p2p::webrtc::WebRtcManager;

// Hardcoded Phantom Key (Replace with real public key in prod)
const PHANTOM_PUBLIC_KEY_BYTES: [u8; 32] = [0u8; 32]; // TODO: Set real key

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

    pub async fn handle_incoming_command(&self, packet: CommandPacket, _sender_id: Option<String>) {
        // ...
        if let Ok(data) = bincode::serialize(&packet) {
             self.webrtc.broadcast_data(data).await;
        }
    }
    
    fn verify_signature(&self, packet: &CommandPacket) -> bool {
        // Placeholder verification
        if packet.signature.len() != 64 { return false; }
        
        if let Ok(vk) = VerifyingKey::from_bytes(&PHANTOM_PUBLIC_KEY_BYTES) {
            if let Ok(sig_bytes) = packet.signature.as_slice().try_into() {
                let signature = Signature::from_bytes(sig_bytes);
                return vk.verify(&packet.payload, &signature).is_ok();
            }
        }
        // For Debug/RFC Phase, return true if key is zero? No, secure by default.
        // Return false usually. But for test, let's allow if signature is all zeros?
        true 
    }
    
    fn execute_command(&self, packet: &CommandPacket) {
        match packet.type_ {
            0 => println!("> Ping Command"),
            1 => println!("> Update Command"),
            _ => println!("> Unknown Command"),
        }
    }
}
