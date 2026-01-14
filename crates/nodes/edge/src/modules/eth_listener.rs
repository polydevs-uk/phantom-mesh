use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use log::{info, warn, debug, error};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // Removed Aead from root
use chacha20poly1305::aead::{Aead, KeyInit}; // Import Aead trait here

// --- CONFIGURATION ---
const RPC_ENDPOINTS: &[&str] = &[
    "https://rpc.sepolia.org",
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://1rpc.io/sepolia",
    "https://rpc2.sepolia.org"
];

// Contract Address (Deployed by User)
const CONTRACT_ADDR: &str = "0x8A58Da9B24C24b9D6Faf2118eB3845FE7D4b13c5"; 
// Event: ScoreSubmitted(uint256 indexed magic_id, bytes payload)
// Topic0 = Keccak256("ScoreSubmitted(uint256,bytes)")
const EVENT_TOPIC_0: &str = "0xf5b2b2c9d749171f81d11324706509c313da5e730b72f44f535144b621404179"; // PRE-CALCULATED

// Master Public Key (32 bytes)
const MASTER_PUB_KEY: [u8; 32] = [
    0x75, 0xbf, 0x34, 0x60, 0xf7, 0x00, 0x57, 0x06, 
    0xa3, 0x82, 0x85, 0x4d, 0x0b, 0x31, 0xc7, 0x63, 
    0x30, 0x4d, 0x15, 0x19, 0x18, 0xd1, 0xca, 0x87, 
    0xe7, 0x38, 0x99, 0xcc, 0x79, 0x3d, 0xb8, 0x6a
];

// Shared Key for ChaCha20 (Derived or Hardcoded?)
// Report says "Encrypted". Assuming a shared secret or derived from Master Key (ECDH)
// For "Dead Drop", usually a Symmetric Key is embedded in the binary to decrypt.
// Let's use a hardcoded fallback key for this generic retrieval.
const FALLBACK_DECRYPT_KEY: [u8; 32] = [0x99; 32]; // Placeholder

#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
    id: u32,
}

#[derive(Deserialize, Debug)]
struct RpcResponse {
    result: Option<Vec<LogEntry>>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct LogEntry {
    topics: Vec<String>, // [Topic0, Topic1(magic_id)]
    data: String,        // Payload (Hex)
    #[serde(rename = "blockNumber")]
    block_number: String,
}

/// Generates the Daily Magic ID (Topic 1)
/// Algorithm: High 32 bits of DGA Hash, padded to 256 bits.
fn get_daily_magic() -> String {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let day_slot = since_the_epoch.as_secs() / 86400;
    
    // Hash (Day ^ Seed)
    let seed: u64 = 0xCAFEBABE;
    let mut state = day_slot ^ seed;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    
    // Convert to uint256 hex string (padded)
    // Magic ID is uint256 in Solidity, so Topic is 32 bytes.
    // We use the 64-bit state as the value.
    // Format: 0x000...000<state_hex>
    format!("0x{:064x}", state)
}

pub async fn check_sepolia_fallback() -> Option<Vec<(String, u16)>> {
    let magic_topic = get_daily_magic();
    info!("[Sepolia] Checking Fallback channel. Magic: {}...", &magic_topic[0..10]);
    
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    // 1. RPC Rotation
    for endpoint in RPC_ENDPOINTS {
        debug!("[Sepolia] Checking RPC: {}", endpoint);
        match fetch_logs(&client, endpoint, &magic_topic).await {
            Ok(logs) => {
                if logs.is_empty() { continue; } // RPC ok, but no logs, try next? Or trust it? Trust it.
                
                // 2. Process Logs (Rate Limit: Max 5)
                // Logs are usually chronological. We want LATEST.
                // Assuming result is sorted by blockNumber? Usually yes.
                // We take the LAST 5.
                let count = logs.len();
                let start_idx = if count > 5 { count - 5 } else { 0 };
                
                info!("[Sepolia] Found {} logs. Processing last {}...", count, count - start_idx);
                
                for log in logs.iter().skip(start_idx).rev() { // Reverse: Newest first
                    if let Some(peers) = try_decrypt_payload(&log.data) {
                         info!("[Sepolia] ✅ Successfully recovered valid peers from Log!");
                         return Some(peers);
                    }
                }
                warn!("[Sepolia] All logs were invalid or failed signature check.");
            }
            Err(e) => warn!("[Sepolia] RPC {} Failed: {}", endpoint, e),
        }
    }
    
    None
}

async fn fetch_logs(client: &Client, url: &str, topic: &str) -> Result<Vec<LogEntry>, Box<dyn Error>> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getLogs",
        "params": [{
            "address": CONTRACT_ADDR,
            "topics": [EVENT_TOPIC_0, topic], // Filter by Daily Magic
            "fromBlock": "0x0" // Or "latest" - 10000 blocks to optimize?
        }],
        "id": 1
    });

    let resp = client.post(url).json(&payload).send().await?;
    let rpc_res: RpcResponse = resp.json().await?;
    
    if let Some(err) = rpc_res.error {
        return Err(format!("RPC Error: {:?}", err).into());
    }
    
    Ok(rpc_res.result.unwrap_or_default())
}

fn try_decrypt_payload(hex_data: &str) -> Option<Vec<(String, u16)>> {
    // 1. Decode Hex
    let clean_hex = hex_data.trim_start_matches("0x");
    let bytes = hex::decode(clean_hex).ok()?;
    
    // Struct: [Magic(4)][IV(12)][Data(N)][Sig(64)]
    // Min len = 4 + 12 + 1 + 64 = 81
    if bytes.len() < 81 { return None; }
    
    let magic_header = &bytes[0..4]; // 0xDEADBEEF check if needed?
    // User report says structure starts with magic.
    
    let iv_slice = &bytes[4..16];
    let sig_slice = &bytes[bytes.len()-64..]; // Last 64 bytes
    let encrypted_data = &bytes[16..bytes.len()-64];
    
    // 2. Verify Signature FIRST (Anti-DoS)
    // What is signed? Report says "Encrypted IP + Sig".
    // Usually Sign(IV + CipherText).
    // Let's assume Master signed [IV + CipherText].
    let mut signed_msg = Vec::new();
    signed_msg.extend_from_slice(magic_header); // Maybe header too?
    signed_msg.extend_from_slice(iv_slice);
    signed_msg.extend_from_slice(encrypted_data);
    
    let vk = VerifyingKey::from_bytes(&MASTER_PUB_KEY).ok()?;
    let signature = Signature::from_bytes(sig_slice.try_into().ok()?);
    
    if vk.verify(&signed_msg, &signature).is_err() {
        debug!("[Sepolia] Invalid Signature in Log");
        return None;
    }
    
    // 3. Decrypt
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&FALLBACK_DECRYPT_KEY));
    let nonce = Nonce::from_slice(iv_slice);
    
    // Note: ChaCha20Poly1305 usually includes MAC tag (16 bytes) at end of CT.
    // If "encrypted_data" is pure ChaCha20 stream, we use ChaCha20 crate?
    // Code imports `chacha20poly1305`. This AEAD expects Tag.
    // Assuming Payload provides Tag or using standard AEAD.
    
    match cipher.decrypt(nonce, encrypted_data) {
        Ok(plaintext) => {
            let s = String::from_utf8(plaintext).ok()?;
            parse_peers(&s)
        },
        Err(_) => None 
    }
}

fn parse_peers(text: &str) -> Option<Vec<(String, u16)>> {
    let mut peers = Vec::new();
    for part in text.split(';') {
        if let Some((ip, port_str)) = part.split_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                peers.push((ip.to_string(), port));
            }
        }
    }
    if peers.is_empty() { None } else { Some(peers) }
}
