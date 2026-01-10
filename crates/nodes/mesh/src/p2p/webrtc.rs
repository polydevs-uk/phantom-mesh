use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::RTCPeerConnection;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct WebRtcManager {
    connections: Arc<Mutex<Vec<Arc<RTCPeerConnection>>>>,
    data_channels: Arc<Mutex<Vec<Arc<RTCDataChannel>>>>, 
}

impl WebRtcManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            data_channels: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn initiate_connection(&self) -> Result<(Arc<RTCPeerConnection>, String), Box<dyn std::error::Error + Send + Sync>> {
        let pc = self.create_pc_internal().await?;
        
        // Data Channel for Initiator
        let dc = pc.create_data_channel("phantom-data", Some(Self::phantom_channel_config()))
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            
        self.register_data_channel(dc, "initiator").await;
        
        let offer = pc.create_offer(None).await?;
        let mut gather_complete = pc.gathering_complete_promise().await;
        pc.set_local_description(offer).await?;
        let _ = gather_complete.recv().await;
        
        if let Some(local_desc) = pc.local_description().await {
            let json_sdp = serde_json::to_string(&local_desc)?;
            self.register_connection(pc.clone()).await;
            return Ok((pc, json_sdp));
        }
        Err("Failed to generate SDP".into())
    }

    pub async fn accept_connection(&self, offer_sdp: &str) -> Result<(Arc<RTCPeerConnection>, String), Box<dyn std::error::Error + Send + Sync>> {
        let pc = self.create_pc_internal().await?;
        
        // On Data Channel (Receiver)
        let dcs = self.data_channels.clone();
        pc.on_data_channel(Box::new(move |d: Arc<RTCDataChannel>| {
            let d_label = d.label().to_owned();
            let d_clone = d.clone();
            let dcs_inner = dcs.clone();
            Box::pin(async move {
                let mut lock = dcs_inner.lock().await;
                lock.push(d_clone);
                println!("[WebRTC] Passive Data Channel opened: {}", d_label);
                let d_label_2 = d_label.clone();
                d.on_message(Box::new(move |msg: webrtc::data_channel::data_channel_message::DataChannelMessage| {
                     let msg_data = msg.data.to_vec();
                     println!("[WebRTC] Msg from {}: {} bytes", d_label_2, msg_data.len());
                     Box::pin(async {})
                }));
            })
        }));

        let offer = serde_json::from_str::<webrtc::peer_connection::sdp::session_description::RTCSessionDescription>(offer_sdp)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            
        pc.set_remote_description(offer).await?;
        
        let answer = pc.create_answer(None).await?;
        let mut gather_complete = pc.gathering_complete_promise().await;
        pc.set_local_description(answer).await?;
        let _ = gather_complete.recv().await;

        if let Some(local_desc) = pc.local_description().await {
             let json_sdp = serde_json::to_string(&local_desc)?;
             self.register_connection(pc.clone()).await;
             return Ok((pc, json_sdp));
        }
        Err("Failed to generate Answer".into())
    }

    async fn create_pc_internal(&self) -> Result<Arc<RTCPeerConnection>, Box<dyn std::error::Error + Send + Sync>> {
         let ice_servers = vec![
            RTCIceServer {
                urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                ..Default::default()
            },
        ];
        let config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut m)?;
        let api = APIBuilder::new()
            .with_media_engine(m)
            .with_interceptor_registry(registry)
            .build();
        let pc = api.new_peer_connection(config).await?;
        Ok(Arc::new(pc))
    }

    async fn register_connection(&self, pc: Arc<RTCPeerConnection>) {
        let mut conns = self.connections.lock().await;
        if conns.len() >= 12 {
             if let Some(old) = conns.get(0) {
                 let _ = old.close().await;
             }
             conns.remove(0);
        }
        conns.push(pc);
    }
    
    async fn register_data_channel(&self, d: Arc<RTCDataChannel>, label: &str) {
        let dcs = self.data_channels.clone();
        let d_clone = d.clone();
        let label_owned = label.to_string();
        tokio::spawn(async move {
            let mut lock = dcs.lock().await;
            lock.push(d_clone);
        });
        
        let label_2 = label_owned.clone();
        d.on_message(Box::new(move |msg: webrtc::data_channel::data_channel_message::DataChannelMessage| {
             let msg_data = msg.data.to_vec();
             println!("[WebRTC] Msg from {}: {} bytes", label_2, msg_data.len());
             Box::pin(async {})
        }));
    }

    pub async fn broadcast_data(&self, data: Vec<u8>) {
        let channels = self.data_channels.lock().await;
        let method_data = bytes::Bytes::from(data);
        for dc in channels.iter() {
            let _ = dc.send(&method_data).await;
        }
    }

    pub fn phantom_channel_config() -> RTCDataChannelInit {
        RTCDataChannelInit {
            ordered: Some(false),
            max_packet_life_time: Some(3000), 
            ..Default::default()
        }
    }
}
