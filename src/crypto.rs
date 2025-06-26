use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::{Nonce, Key};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey, gen_keypair};
use std::fs;

pub fn init() {
    sodiumoxide::init().expect("Failed to initialize sodiumoxide");
}

// === File (Shard) Encryption ===

pub fn gen_key() -> Key {
    secretbox::gen_key()
}

pub fn gen_nonce() -> Nonce {
    secretbox::gen_nonce()
}

// Encrypt a file (shard) in-place with XSalsa20-Poly1305
pub fn encrypt_shard_file(path: &str) -> std::io::Result<()> {
    let key = get_or_generate_key_for_file(path)?;
    let nonce = gen_nonce();
    let data = fs::read(path)?;
    let ciphertext = secretbox::seal(&data, &nonce, &key);

    // Save nonce+ciphertext together
    let mut out = nonce.0.to_vec();
    out.extend(ciphertext);

    fs::write(path, out)?;
    Ok(())
}

// Decrypt a file (shard) and return bytes
pub fn decrypt_shard_file(path: &str) -> std::io::Result<Vec<u8>> {
    let key = get_or_generate_key_for_file(path)?;
    let bytes = fs::read(path)?;
    if bytes.len() < secretbox::NONCEBYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Not enough bytes for nonce + ciphertext",
        ));
    }
    let (nonce_bytes, ciphertext) = bytes.split_at(secretbox::NONCEBYTES);
    let nonce = Nonce::from_slice(nonce_bytes).unwrap();
    secretbox::open(ciphertext, &nonce, &key)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Decryption failed"))
}

// Save/load key for a file (demo: key per file, saved as .key file)
fn get_or_generate_key_for_file(path: &str) -> std::io::Result<Key> {
    let key_path = format!("{}.key", path);
    if let Ok(key_bytes) = fs::read(&key_path) {
        if let Some(key) = Key::from_slice(&key_bytes) {
            return Ok(key);
        }
    }
    // Generate new key
    let key = gen_key();
    fs::write(&key_path, &key.0)?;
    Ok(key)
}

// === User Keypair (for messaging) ===

pub fn gen_user_keypair() -> (PublicKey, SecretKey) {
    gen_keypair()
}

pub fn save_keypair(pk: &PublicKey, sk: &SecretKey, prefix: &str) -> std::io::Result<()> {
    fs::write(format!("{}.pk", prefix), pk.0)?;
    fs::write(format!("{}.sk", prefix), sk.0)
}

pub fn load_keypair(prefix: &str) -> std::io::Result<(PublicKey, SecretKey)> {
    let pk = fs::read(format!("{}.pk", prefix))?;
    let sk = fs::read(format!("{}.sk", prefix))?;
    Ok((
        PublicKey::from_slice(&pk).unwrap(),
        SecretKey::from_slice(&sk).unwrap(),
    ))
}
