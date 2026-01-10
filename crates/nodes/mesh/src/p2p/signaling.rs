use libp2p::{
    gossipsub, noise, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, Swarm, SwarmBuilder,
};
use libp2p::futures::StreamExt;
use std::time::Duration;
use tokio::sync::mpsc;
use protocol::SignalEnvelope;

// Layer 2: Signaling Manager

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "MyBehaviourEvent")]
pub struct MyBehaviour {
    pub gossipsub: gossipsub::Behaviour,
}

#[derive(Debug)]
pub enum MyBehaviourEvent {
    Gossipsub(gossipsub::Event),
}

impl From<gossipsub::Event> for MyBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        MyBehaviourEvent::Gossipsub(event)
    }
}

pub struct SignalingManager {
    swarm: Swarm<MyBehaviour>,
    topic: gossipsub::IdentTopic,
    pub command_tx: mpsc::Sender<SignalingCommand>,
    command_rx: mpsc::Receiver<SignalingCommand>,
    pub signal_output_tx: mpsc::Sender<(String, SignalEnvelope)>, // (PeerId, Envelope)
}



pub enum SignalingCommand {
    PublishSignal(SignalEnvelope),
    Dial(libp2p::Multiaddr),
    Shutdown,
}

impl SignalingManager {
    pub fn new(local_key: libp2p::identity::Keypair, topic_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key: &libp2p::identity::Keypair| {
                 let message_id_fn = |message: &gossipsub::Message| {
                     let mut s = std::collections::hash_map::DefaultHasher::new();
                     use std::hash::{Hash, Hasher};
                     message.data.hash(&mut s);
                     gossipsub::MessageId::from(s.finish().to_string())
                 };
                 let gossipsub_config = gossipsub::ConfigBuilder::default()
                     .heartbeat_interval(Duration::from_secs(1)) 
                     .validation_mode(gossipsub::ValidationMode::Strict) 
                     .message_id_fn(message_id_fn) 
                     .build()
                     .map_err(|msg| std::io::Error::new(std::io::ErrorKind::Other, msg))?;
                 let gossipsub = gossipsub::Behaviour::new(
                     gossipsub::MessageAuthenticity::Signed(key.clone()),
                     gossipsub_config,
                 )?;
                 Ok(MyBehaviour { gossipsub })
            })?
            .build();
            
        let topic = gossipsub::IdentTopic::new(topic_str);
        
        let (tx, rx) = mpsc::channel(32);
        let (out_tx, _) = mpsc::channel(32); // Placeholder, run_loop will receive clone or we return receiver
        
        Ok(Self {
            swarm,
            topic,
            command_tx: tx,
            command_rx: rx,
            signal_output_tx: out_tx, // Temporary, will fix interface below
        })
    }
    
    // Better API: new returns (Self, Sender, Receiver)
    pub fn new_with_channel(local_key: libp2p::identity::Keypair, topic_str: &str, listen_port: u16) 
        -> Result<(Self, mpsc::Sender<SignalingCommand>, mpsc::Receiver<(String, SignalEnvelope)>), Box<dyn std::error::Error>> 
    {
         // Same setup
         let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key: &libp2p::identity::Keypair| {
                 let message_id_fn = |message: &gossipsub::Message| {
                     let mut s = std::collections::hash_map::DefaultHasher::new();
                     use std::hash::{Hash, Hasher};
                     message.data.hash(&mut s);
                     gossipsub::MessageId::from(s.finish().to_string())
                 };
                 let gossipsub_config = gossipsub::ConfigBuilder::default()
                     .heartbeat_interval(Duration::from_secs(1)) 
                     .validation_mode(gossipsub::ValidationMode::Strict) 
                     .message_id_fn(message_id_fn) 
                     .build()
                     .map_err(|msg| std::io::Error::new(std::io::ErrorKind::Other, msg))?;
                 let gossipsub = gossipsub::Behaviour::new(
                     gossipsub::MessageAuthenticity::Signed(key.clone()),
                     gossipsub_config,
                 )?;
                 Ok(MyBehaviour { gossipsub })
            })?
            .build();
            
        let topic = gossipsub::IdentTopic::new(topic_str);
        
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (sig_tx, sig_rx) = mpsc::channel(32);
        
        let mut manager = Self {
            swarm,
            topic,
            command_tx: cmd_tx.clone(),
            command_rx: cmd_rx,
            signal_output_tx: sig_tx,
        };
        
        // Listen on specific port
        let addr = format!("/ip4/0.0.0.0/tcp/{}", listen_port).parse()?;
        manager.swarm.listen_on(addr)?;
        
        Ok((manager, cmd_tx, sig_rx))
    }

    pub async fn run_loop(mut self) {
        let _ = self.swarm.behaviour_mut().gossipsub.subscribe(&self.topic);
        // listen_on is called in new() now to ensure binding before return.

        
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                         propagation_source: peer_id,
                         message_id: _id,
                         message,
                    })) => {
                        println!("[Signaling] Received Msg from {}: {} bytes", peer_id, message.data.len());
                        if let Ok(envelope) = bincode::deserialize::<SignalEnvelope>(&message.data) {
                            let _ = self.signal_output_tx.send((peer_id.to_string(), envelope)).await;
                        }
                    },
                    // ...
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("[Signaling] Listening on {:?}", address);
                    },
                    _ => {}
                },
                
                cmd = self.command_rx.recv() => match cmd {
                    Some(SignalingCommand::PublishSignal(envelope)) => {
                        if let Ok(data) = bincode::serialize(&envelope) {
                            let _ = self.swarm.behaviour_mut().gossipsub.publish(self.topic.clone(), data);
                        }
                    },
                    Some(SignalingCommand::Dial(addr)) => {
                        println!("[Signaling] Dialing {}", addr);
                        let _ = self.swarm.dial(addr);
                    },
                    Some(SignalingCommand::Shutdown) | None => break,
                }
            }
        }
    }
}
