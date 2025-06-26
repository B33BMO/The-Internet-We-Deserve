use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey, Nonce};
use sodiumoxide::randombytes;

pub async fn send_message(recipient: &str, message: &str) -> anyhow::Result<()> {
    // Load your keypair
    let (my_pk, my_sk) = crate::crypto::load_keypair("me")?;
    // Load recipient's public key
    let recip_pk_bytes = std::fs::read(format!("{}.pk", recipient))?;
    let recip_pk = PublicKey::from_slice(&recip_pk_bytes).unwrap();

    // Encrypt
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(message.as_bytes(), &nonce, &recip_pk, &my_sk);

    // Bundle as [nonce][ciphertext]
    let mut msg = nonce.0.to_vec();
    msg.extend(ciphertext);

    // TODO: Actually deliver via mesh—here, we’ll just save as a file for now
    let out_path = format!("{}_to_{}.msg", crate::utils::now_timestamp(), recipient);
    std::fs::write(&out_path, msg)?;

    println!("(Stub) Encrypted message written to {}", out_path);
    Ok(())
}

pub fn receive_message(from: &str, msg_path: &str) -> anyhow::Result<String> {
    let (my_pk, my_sk) = crate::crypto::load_keypair("me")?;
    let sender_pk_bytes = std::fs::read(format!("{}.pk", from))?;
    let sender_pk = PublicKey::from_slice(&sender_pk_bytes).unwrap();

    let msg_bytes = std::fs::read(msg_path)?;
    if msg_bytes.len() < box_::NONCEBYTES {
        return Err(anyhow::anyhow!("Invalid message format"));
    }
    let (nonce_bytes, ciphertext) = msg_bytes.split_at(box_::NONCEBYTES);
    let nonce = Nonce::from_slice(nonce_bytes).unwrap();

    let plaintext = box_::open(ciphertext, &nonce, &sender_pk, &my_sk)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))?;
    Ok(String::from_utf8_lossy(&plaintext).to_string())
}
