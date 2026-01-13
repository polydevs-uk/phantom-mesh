use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use log::{info, error, debug};
use crate::client::PolyMqttClient; // Assumption: We can use the client

pub struct BridgeService {
    cloud_client: Arc<PolyMqttClient>,
}

impl BridgeService {
    pub fn new(cloud_client: Arc<PolyMqttClient>) -> Self {
        Self { cloud_client }
    }

    /// Handle a new Worker connection (UDS)
    pub async fn handle_worker(&self, mut stream: UnixStream) {
        info!("[Bridge] New Worker Connected");
        
        let mut buf = [0u8; 4096];
        
        loop {
            // 1. Read from Worker
            match stream.read(&mut buf).await {
                Ok(0) => return, // Closed
                Ok(n) => {
                    let data = &buf[..n];
                    debug!("[Bridge] Recv {} bytes from Worker", n);
                    
                    // 2. Forward to Cloud (Encrypted Traffic)
                    // The Worker should probably have already encrypted it? 
                    // Or Leader encrypts?
                    // V2 Spec: "Worker connects to Leader... Leader sends to Cloud".
                    // If Worker has no Internet, it can't handshake Cloud.
                    // So Leader acts as Transparent Proxy or VPN.
                    // Simplified: Leader encrypts on behalf of Worker (Shared Key Model)
                    // OR Worker encrypts payload, Leader wraps it.
                    
                    let res = self.cloud_client.send_secure_payload(data).await;
                    if let Err(e) = res {
                        error!("[Bridge] Failed to forward to Cloud: {}", e);
                    }
                }
                Err(e) => {
                    error!("[Bridge] Worker Read Error: {}", e);
                    return;
                }
            }
        }
    }
}
