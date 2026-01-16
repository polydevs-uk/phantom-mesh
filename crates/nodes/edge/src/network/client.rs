use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::error::Error;
use log::{info, warn, debug, error};
use rand::RngCore;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use tokio::sync::mpsc;

use protocol::uplink::MqttPacket;

// Removed local MQTT_PUBLISH constant as it's now in uplink
const AUTH_TOPIC: &str = "dev/sys/log";

pub struct PolyMqttClient {
    iot_ip: String,
    iot_port: u16,
    master_key: Key, 
}

impl PolyMqttClient {
    pub fn new(iot_ip: &str, iot_port: u16, key_bytes: &[u8; 32]) -> Self {
        Self {
            iot_ip: iot_ip.to_string(),
            iot_port,
            master_key: *Key::from_slice(key_bytes), // chacha key
        }
    }

    pub async fn send_secure_payload(&self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let addr = format!("{}:{}", self.iot_ip, self.iot_port);
        let mut stream = TcpStream::connect(&addr).await?;
        self.write_packet(&mut stream, data).await?;
        Ok(())
    }

    pub async fn start_persistent_loop(
        &self, 
        mut msg_rx: mpsc::Receiver<Vec<u8>>,
        cmd_tx: mpsc::Sender<Vec<u8>>
    ) {
        let addr = format!("{}:{}", self.iot_ip, self.iot_port);
        info!("[PolyClient] Starting Persistent Loop for {}", addr);

        loop { // reconnect
            match TcpStream::connect(&addr).await {
                Ok(mut stream) => {
                    info!("[PolyClient] Connected to Cloud.");
                    
                    let (mut reader, mut writer) = stream.split();
                    
                    // handshake goes here if needed

                    loop { // Data Loop
                        tokio::select! {
                            // 1. Outgoing Message
                            Some(payload) = msg_rx.recv() => {
                                // We need to re-unify logic or use write_packet on the WriteHalf
                                // write_packet needs &mut TcpStream, but we have WriteHalf.
                                // Refactoring write_packet to generic AsyncWriteExt
                                if let Err(e) = self.write_frame(&mut writer, &payload).await {
                                    error!("[PolyClient] Write Error: {}", e);
                                    break; // Reconnect
                                }
                            }

                            // 2. Incoming Message
                            res = self.read_frame(&mut reader) => {
                                match res {
                                    Ok(payload) => {
                                        debug!("[PolyClient] Recv {} bytes from Cloud", payload.len());
                                        if let Err(_) = cmd_tx.send(payload).await {
                                            break; // Main app closed
                                        }
                                    }
                                    Err(e) => {
                                        error!("[PolyClient] Read Error: {}", e);
                                        break; // Reconnect
                                    }
                                }
                            }
                        }
                    }
                    warn!("[PolyClient] Connection Lost. Reconnecting in 5s...");
                }
                Err(e) => {
                    warn!("[PolyClient] Connect Failed: {}. Retrying in 5s...", e);
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }

    /// Generic Write Frame (Encrypts + MQTT Wrap)
    async fn write_frame<W>(&self, writer: &mut W, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> 
    where W: AsyncWriteExt + Unpin 
    {
        // 1. Encrypt
        let cipher = ChaCha20Poly1305::new(&self.master_key);
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Encryption failure: {}", e)))?;

        // 2. Prepend Nonce to Ciphertext (Nonce + Ciphertext)
        let mut final_payload = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        final_payload.extend_from_slice(&nonce_bytes);
        final_payload.extend_from_slice(&ciphertext);

        // 3. Construct MQTT Packet
        let packet = MqttPacket::new(AUTH_TOPIC, final_payload).to_bytes()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        writer.write_all(&packet).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Generic Read Frame (MQTT Unwrap)
    /// Note: Currently assumes UNENCRYPTED response from Cloud (or minimal obfuscation),
    /// since Cloud->Edge encryption might be separate. 
    /// If Cloud sends MQTT PUBLISH back, we parse it.
    async fn read_frame<R>(&self, reader: &mut R) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>
    where R: AsyncReadExt + Unpin
    {
        // 1. Read Fixed Header + Length to know how much to buffer
        // For simplicity/robustness, we might need a better framing reader.
        // But MqttPacket::parse takes a buffer.
        // We act as a "Byte Stream" to "Packet" decoder here.
        
        // Peek or Read minimal? 
        // Let's keep strict read flow for now but verify header.
        let mut head = [0u8; 1];
        reader.read_exact(&mut head).await?;
        if (head[0] & 0xF0) != 0x30 {
             // Basic pre-check failed
        }
        
        // Need to read variable length to know total frame size
        let len = self.decode_var_length(reader).await?;
        
        // Construct full buffer for parser (Header + VarLen + Remainder)
        // Optimization: Just read Remainder and let parser handle payload logic?
        // MqttPacket::parse expects Full Packet (including header).
        // Reuse internal logic or just read body?
        // Since we already consumed Header + VarLen, let's just read body explicitly.
        
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).await?;
        
        // Manually reconstructing packet for verify? Or just parse body components?
        // MqttPacket::parse expects full buffer. 
        // Let's implement MqttPacket::from_parts if needed, or just extract here.
        
        // Manual extraction strictly matching Uplink spec
        if body.len() < 2 { return Err("Body too short".into()); }
        let topic_len = ((body[0] as usize) << 8) | (body[1] as usize);
        if body.len() < 2 + topic_len { return Err("Body shorter than topic".into()); }
        
        let encrypted_payload = &body[2 + topic_len..];
        
        if encrypted_payload.len() < 12 {
             return Err("Payload too short for Nonce".into());
        }

        // 1. Extract Nonce (first 12 bytes)
        let nonce = Nonce::from_slice(&encrypted_payload[0..12]);
        let ciphertext = &encrypted_payload[12..];

        // 2. Decrypt
        let cipher = ChaCha20Poly1305::new(&self.master_key);
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Decryption failure: {}", e)))?;

        Ok(plaintext)
    }

    // Helper for Write (keeps compatibility for old send_secure_payload call)
    async fn write_packet(&self, stream: &mut TcpStream, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.write_frame(stream, data).await
    }



    async fn decode_var_length<R>(&self, reader: &mut R) -> Result<usize, Box<dyn Error + Send + Sync>>
    where R: AsyncReadExt + Unpin
    {
        let mut multiplier = 1;
        let mut value = 0;
        loop {
            let mut b = [0u8; 1];
            reader.read_exact(&mut b).await?;
            value += ((b[0] & 127) as usize) * multiplier;
            if (b[0] & 128) == 0 { break; }
            multiplier *= 128;
            if multiplier > 128*128*128 { return Err("VarLen Too Big".into()); }
        }
        Ok(value)
    }
}
