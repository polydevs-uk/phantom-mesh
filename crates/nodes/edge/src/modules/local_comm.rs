use tokio::net::{UnixListener, UnixStream};
use std::error::Error;
use log::{info, error};
use std::os::unix::fs::PermissionsExt;

// On Windows this would be Named Pipe. On Mac/Linux, UDS.
const SOCK_PATH: &str = "/tmp/phantom_edge.sock";

pub struct LocalTransport;

impl LocalTransport {
    pub async fn bind_server() -> Result<UnixListener, Box<dyn Error + Send + Sync>> {
        // Clean up old socket
        let _ = std::fs::remove_file(SOCK_PATH);

        let listener = UnixListener::bind(SOCK_PATH)?;
        
        // Set permissions (777 for demo simplifiction)
        let mut perms = std::fs::metadata(SOCK_PATH)?.permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(SOCK_PATH, perms)?;

        info!("[LocalComm] Bound UDS Server at {}", SOCK_PATH);
        Ok(listener)
    }

    pub async fn connect_client() -> Result<UnixStream, Box<dyn Error + Send + Sync>> {
        let stream = UnixStream::connect(SOCK_PATH).await?;
        info!("[LocalComm] Connected to Leader via UDS");
        Ok(stream)
    }
}
