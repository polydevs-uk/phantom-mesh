use async_trait::async_trait;
use reqwest::Client;
use std::error::Error;
use serde::Deserialize;
use super::BootstrapProvider;

pub struct HttpProvider {
    pub url: String,
}

#[async_trait]
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

#[async_trait]
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
