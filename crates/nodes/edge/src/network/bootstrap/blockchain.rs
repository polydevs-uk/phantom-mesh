use async_trait::async_trait;
use reqwest::Client;
use std::error::Error;
use super::BootstrapProvider;

/// Blockchain Fallback Provider (Sepolia)
pub struct EthProvider;

#[async_trait]
impl BootstrapProvider for EthProvider {
    async fn fetch_payload(&self, _client: &Client) -> Result<String, Box<dyn Error + Send + Sync>> {
         Err("Use explicit Tier 3 call".into())
    }

    fn name(&self) -> String {
        "Ethereum Sepolia (Fallback)".to_string()
    }
}
