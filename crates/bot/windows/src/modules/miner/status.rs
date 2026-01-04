use crate::common::constants::get_miner_exe_name;
#[cfg(not(windows))]
use crate::utils::paths::get_all_install_dirs;

#[cfg(windows)]
pub fn check_status() {
    use std::process::Command;
    
    if let Ok(output) = Command::new("tasklist")
        .args(&["/FI", &format!("IMAGENAME eq {}", get_miner_exe_name())])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains(&get_miner_exe_name()) {
            println!("RUNNING");
        } else {
            println!("STOPPED");
        }
    } else {
        println!("UNKNOWN");
    }
}

#[cfg(not(windows))]
pub fn check_status() {
    let install_dirs = get_all_install_dirs();
    let installed = install_dirs.iter().any(|d| d.exists());
    
    if installed {
        println!("INSTALLED (Linux/Mac Check)");
    } else {
        println!("NOT_INSTALLED");
    }
}
