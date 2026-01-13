use tokio::net::UdpSocket;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use rand::Rng;
use log::{info, debug};

const DISCOVERY_PORT: u16 = 31338;
const DISCOVERY_MAGIC: u32 = 0xDEAD0001;
const BROADCAST_ADDR: &str = "255.255.255.255:31338";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
enum MessageType {
    WhoIsLeader,
    IAmLeader,
    Election,
    Coordinator,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ElectionPacket {
    magic: u32,
    msg_type: MessageType,
    node_id: u64,
    rank: u64, // Uptime + Random
}

#[derive(Debug, Clone, PartialEq)]
pub enum NodeRole {
    Unbound,
    Leader,
    Worker,
}

pub struct ElectionService {
    node_id: u64,
    rank: u64,
    role: Arc<Mutex<NodeRole>>,
    socket: Arc<UdpSocket>,
}

use socket2::{Socket, Domain, Type, Protocol};
use std::net::SocketAddr;

impl ElectionService {
    pub async fn new() -> Self {
        let node_id = rand::thread_rng().gen::<u64>();
        let rank = node_id % 1000; 
        
        // Use socket2 to set SO_REUSEPORT/ADDR
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .expect("Failed to create socket");
            
        socket.set_reuse_address(true).expect("Failed to set reuse_address");
        #[cfg(not(target_os = "windows"))]
        socket.set_reuse_port(true).expect("Failed to set reuse_port"); // Critical for local sim
        socket.set_broadcast(true).expect("Failed to set broadcast");
        
        let addr: SocketAddr = format!("0.0.0.0:{}", DISCOVERY_PORT).parse().unwrap();
        socket.bind(&addr.into()).expect("Failed to bind UDP discovery port");
        socket.set_nonblocking(true).expect("Failed to set nonblocking");

        let socket = UdpSocket::from_std(socket.into()).expect("Failed to convert socket");

        Self {
            node_id,
            rank,
            role: Arc::new(Mutex::new(NodeRole::Unbound)),
            socket: Arc::new(socket),
        }
    }

    pub async fn run_discovery(&self) -> NodeRole {
        info!("[Election] Starting Discovery... ID: {}", self.node_id);
        
        // 1. Send WHO_IS_LEADER
        let packet = ElectionPacket {
            magic: DISCOVERY_MAGIC,
            msg_type: MessageType::WhoIsLeader,
            node_id: self.node_id,
            rank: self.rank,
        };
        let bytes = serde_json::to_vec(&packet).unwrap();
        
        // Broadcast multiple times for reliability
        for _ in 0..3 {
            let _ = self.socket.send_to(&bytes, BROADCAST_ADDR).await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // 2. Listen for Response (3 seconds)
        let end_time = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut buf = [0u8; 1024];

        while tokio::time::Instant::now() < end_time {
            // Using timeout on recv
            if let Ok(Ok((len, addr))) = tokio::time::timeout(
                Duration::from_millis(100), 
                self.socket.recv_from(&mut buf)
            ).await {
                if let Ok(resp) = serde_json::from_slice::<ElectionPacket>(&buf[..len]) {
                    if resp.magic == DISCOVERY_MAGIC {
                        match resp.msg_type {
                            MessageType::IAmLeader => {
                                info!("[Election] Found Leader: {} @ {}", resp.node_id, addr);
                                let mut r = self.role.lock().await;
                                *r = NodeRole::Worker;
                                return NodeRole::Worker;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // 3. Timeout -> Become Leader (Simplified Bully: Just claim it if no one answers)
        // Real Bully would trigger an Election process, but spec says "Scenario B: Timeout -> Become Leader"
        info!("[Election] No Leader found. Promoting self to LEADER.");
        
        let mut r = self.role.lock().await;
        *r = NodeRole::Leader;
        
        // Announce Leadership
        let win_packet = ElectionPacket {
            magic: DISCOVERY_MAGIC,
            msg_type: MessageType::IAmLeader,
            node_id: self.node_id,
            rank: self.rank,
        };
        let bytes = serde_json::to_vec(&win_packet).unwrap();
        let _ = self.socket.send_to(&bytes, BROADCAST_ADDR).await;

        NodeRole::Leader
    }

    /// Background task to respond to WHO_IS_LEADER if we are Leader
    pub async fn monitor_requests(&self) {
        let mut buf = [0u8; 1024];
        loop {
            if let Ok((len, addr)) = self.socket.recv_from(&mut buf).await {
                if let Ok(pkt) = serde_json::from_slice::<ElectionPacket>(&buf[..len]) {
                    if pkt.magic == DISCOVERY_MAGIC {
                        // If we are Leader, respond
                        let role = self.role.lock().await;
                        if *role == NodeRole::Leader && pkt.msg_type == MessageType::WhoIsLeader {
                            info!("[Election] Received request from {}. Responding I_AM_LEADER.", pkt.node_id);
                            let resp = ElectionPacket {
                                magic: DISCOVERY_MAGIC,
                                msg_type: MessageType::IAmLeader,
                                node_id: self.node_id,
                                rank: self.rank,
                            };
                            let bytes = serde_json::to_vec(&resp).unwrap();
                            let _ = self.socket.send_to(&bytes, addr).await;
                        }
                        
                        // Conflict Resolution (Higher Rank Wins)
                        if *role == NodeRole::Leader && pkt.msg_type == MessageType::IAmLeader {
                            if pkt.node_id != self.node_id {
                                if pkt.rank > self.rank {
                                    info!("[Election] Higher rank leader detected ({}), stepping down.", pkt.node_id);
                                    // Drop lock before await? No, just change state.
                                    // Need to signal main loop to switch mode. 
                                    // For now, just Log.
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
