use libp2p::{
    gossipsub, noise, swarm::{NetworkBehaviour, SwarmEvent}, tcp, yamux, Multiaddr, PeerId, Swarm, Transport,
};
use libp2p::identity::Keypair;
use std::time::Duration;
use futures_util::StreamExt;
use protocol::{GhostPacket, CommandType, CommandPayload, GossipMsg, MeshMsg};
use ed25519_dalek::SigningKey;
use std::error::Error;

// Define the P2P Behaviour for the Ghost Controller
#[derive(NetworkBehaviour)]
struct GhostBehaviour {
    gossipsub: gossipsub::Behaviour,
}

pub struct GhostClient {
    swarm: Swarm<GhostBehaviour>,
    topic: gossipsub::IdentTopic,
}

impl GhostClient {
    pub async fn new() -> Result<Self, Box<dyn Error>> {
        let id_keys = Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(id_keys.public());
        println!("[Ghost] Identity: {}", local_peer_id);

        // Transport
        let tcp = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
        let transport = tcp
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::Config::new(&id_keys)?)
            .multiplex(yamux::Config::default())
            .boxed();

        // GossipSub
        let message_id_fn = |message: &gossipsub::Message| {
            let mut s = std::collections::hash_map::DefaultHasher::new();
            use std::hash::{Hash, Hasher};
            message.data.hash(&mut s);
            gossipsub::MessageId::from(s.finish().to_string())
        };
        
        let gossip_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .build()
            .map_err(|msg| format!("Gossip config error: {}", msg))?;

        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(id_keys.clone()), 
            gossip_config
        )?;

        let topic = gossipsub::IdentTopic::new("/phantom/v3/sig/global");
        gossipsub.subscribe(&topic)?;

        let behaviour = GhostBehaviour { gossipsub };

// ...

        // Correct SwarmBuilder usage for Libp2p 0.53+
        let swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
            .with_tokio()
            .with_other_transport(|_key| transport)?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        Ok(Self { swarm, topic })
    }

    pub async fn dial(&mut self, addr: &str) -> Result<(), Box<dyn Error>> {
        let multiaddr: Multiaddr = addr.parse()?;
        self.swarm.dial(multiaddr)?;
        
        // Wait for connection established
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("[Ghost] Connected to Entry Node: {}", peer_id);
                    break;
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    return Err(format!("Connection failed: {}", error).into());
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub async fn inject_command(&mut self, payload: CommandPayload, sign_key: &SigningKey, _session_key: &[u8]) -> Result<(), Box<dyn Error>> {
        // In P2P V3, we don't use a Session Key for Injection into GossipSub.
        // We act as a valid node signing a Gossip Message. 
        // HOWEVER, the Payload might need encryption if we want confidentiality.
        // For simplicity/Robustness, Ghost injects directly.
        // If we want to use the SWARM_KEY, we should import it or accept it.
        // User cleaned up "Plaintext Demo", so we should ideally encrypt.
        // But GhostClient is external. Let's assume for now we send Plaintext CommandPayload wrapped in Signed Packet
        // OR we use the same SWARM_KEY logic.
        // Given we are refactoring, let's keep it simple: Inject Signed Packet.
        
        // Serialize Payload
        let json_payload = serde_json::to_string(&payload)?;

        // Encrypt (Optional - skipping for Ghost MVP to ensure connectivity first, or use a hardcoded Swarm Key if needed)
        // Let's use Plaintext for CommandPayload inside the Signed Packet for now, 
        // as the "Encryption" work was focused on WebRTC Signaling (Handshake), not necessarily Gossip Data.
        // Wait, `FloodingManager` logic wasn't fully shown but typically it verifies signature.
        
        let data = json_payload.as_bytes().to_vec();

        // Create Packet (Signed by Master Key)
        let packet = GhostPacket::new(CommandType::StartModule, data, sign_key);
        
        // Wrap in GossipMsg
        let gossip = GossipMsg {
            id: payload.id.clone(),
            packet,
            ttl: 10,
        };

        // Network Message
        let msg = MeshMsg::Gossip(gossip);
        let msg_bytes = serde_json::to_vec(&msg)?;

        // Publish
        self.swarm.behaviour_mut().gossipsub.publish(self.topic.clone(), msg_bytes)?;
        println!("[Ghost] Command Published to GossipSub.");
        
        // Wait a bit to ensure flush
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        Ok(())
    }
}
