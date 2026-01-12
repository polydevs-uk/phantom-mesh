use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicI64, Ordering};
use sntpc::NtpContext;
use std::net::UdpSocket;
use chrono::{DateTime, Utc};

// Global offset: NetworkTime - SystemTime
static TIME_OFFSET: AtomicI64 = AtomicI64::new(0);
static LAST_SYNC: AtomicI64 = AtomicI64::new(0);

pub struct TimeKeeper;

impl TimeKeeper {
    /// Initialize time sync. Tries to sync, falls back to OS time if fails.
    pub async fn init() {
        for _ in 0..3 {
            if Self::synchronize().await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    /// Update the global time offset and potentially correct the OS time
    pub async fn synchronize() -> Result<(), String> {
        let network_time = match Self::get_ntp_time() {
            Ok(t) => t,
            Err(e) => return Err(e),
        };

        let system_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let offset = network_time - system_time;
        TIME_OFFSET.store(offset, Ordering::SeqCst);
        LAST_SYNC.store(system_time, Ordering::SeqCst);

        Ok(())
    }

    /// Get current verified UTC time
    pub fn utc_now() -> DateTime<Utc> {
        let ts = Self::get_synced_time_secs() as i64;
        DateTime::from_timestamp(ts, 0).unwrap_or_else(Utc::now)
    }
    
    /// Get NTP-corrected time in seconds since UNIX Epoch
    pub fn get_synced_time_secs() -> u64 {
        let sys_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
            
        let offset = TIME_OFFSET.load(Ordering::SeqCst);
        let corrected_ts = sys_time + offset;
        
        corrected_ts as u64
    }

    fn get_ntp_time() -> Result<i64, String> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        socket.set_read_timeout(Some(Duration::from_secs(2))).ok();
        
        let pool = ["pool.ntp.org", "time.google.com", "time.windows.com"];
        
        for server in pool {
            let context = NtpContext::new(StdTimestampGen);
            if let Ok(result) = sntpc::get_time(server, &socket, context) {
                return Ok(result.sec() as i64);
            }
        }
        Err("All NTP servers failed".into())
    }
}

// Helper for sntpc
#[derive(Copy, Clone)]
struct StdTimestampGen;
impl sntpc::NtpTimestampGenerator for StdTimestampGen {
    fn init(&mut self) {}
    fn timestamp_sec(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
    fn timestamp_subsec_micros(&self) -> u32 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_micros()
    }
}
