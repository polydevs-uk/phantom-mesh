use chrono::prelude::*;
use sha1::{Digest, Sha1};
use crate::time::TimeKeeper;
use reqwest::Client;


pub struct Oracle;

impl Oracle {
    /// Generate Financial-DGA InfoHash based on Yesterday's BTC/ETH Close Price
    /// Formula: SHA1(Salt + Date_UTC + String(P_BTC ^ P_ETH))
    pub async fn generate_financial_hash() -> Result<[u8; 20], Box<dyn std::error::Error + Send + Sync>> {
        let utc = TimeKeeper::utc_now();
        // T-1 (Yesterday)
        let yesterday = utc - chrono::Duration::days(1);
        let date_str = utc.format("%Y-%m-%d").to_string(); // Date used in Hash is TODAY (per Spec)
        
        // Salt + Today + (Yesterday_Price).
        let (btc_price, eth_price) = Self::fetch_prices(&yesterday).await?;
        
        let mix_price = btc_price ^ eth_price;
        let salt = b"Phantom_v3_Core";
        
        // Input: Salt + Date + Mix
        let raw_input = format!("{}{}{}", String::from_utf8_lossy(salt), date_str, mix_price);
        
        let mut hasher = Sha1::new();
        hasher.update(raw_input.as_bytes());
        let result = hasher.finalize();
        
        println!("[Oracle] Financial DGA: Date={} BTC={} ETH={} Mix={} Hash={}", 
            date_str, btc_price, eth_price, mix_price, hex::encode(result));

        Ok(result.into())
    }

    async fn fetch_prices(_date: &DateTime<Utc>) -> Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>> {
        let client = Client::new();
        
        let btc = Self::fetch_price(&client, "BTCUSDT").await?;
        let eth = Self::fetch_price(&client, "ETHUSDT").await?;
        
        Ok((btc, eth))
    }
    
    async fn fetch_price(client: &Client, symbol: &str) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("https://api.binance.com/api/v3/klines?symbol={}&interval=1d&limit=2", symbol);
        let res = client.get(&url).timeout(std::time::Duration::from_secs(10)).send().await?;
        let json: serde_json::Value = res.json().await?;
        
        // Extract 4th element of 1st item (Yesterday)
        if let Some(klines) = json.as_array() {
            if let Some(yesterday) = klines.first() { // Index 0 is T-1
                if let Some(close_str_val) = yesterday.get(4) {
                     if let Some(s) = close_str_val.as_str() {
                         let price_f: f64 = s.parse()?;
                         return Ok(price_f.floor() as u64);
                     }
                }
            }
        }
        
        // Fallback
        eprintln!("[Oracle] Failed to fetch {} from Binance. Using Fallback.", symbol);
        match symbol {
            "BTCUSDT" => Ok(45000),
            "ETHUSDT" => Ok(3000),
            _ => Ok(0)
        }
    }
}
