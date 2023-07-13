use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

mod crypto;

fn main() -> crypto::CryptoResult<()> {
    let primary_private = crypto::generate_key()?;
    let primary_public = crypto::public_key(&primary_private)?;

    let primary_private_pem = crypto::export_private_key(&primary_private)?;
    let primary_public_pem = crypto::export_public_key(&primary_public)?;
    println!(
        "Alice's Keys (Fingerprint: {}):\n{primary_private_pem}{primary_public_pem}",
        crypto::fingerprint(&primary_public)?
    );

    let ephemeral_private = crypto::generate_key()?;
    let ephemeral_public = crypto::public_key(&ephemeral_private)?;

    let ephemeral_private_pem = crypto::export_private_key(&ephemeral_private)?;
    let ephemeral_public_pem = crypto::export_public_key(&ephemeral_public)?;
    println!(
        "Bob's Keys (Fingerprint: {}):\n{ephemeral_private_pem}{ephemeral_public_pem}",
        crypto::fingerprint(&ephemeral_public)?
    );

    let ecdh_bytes = crypto::ecdh(&primary_private, &ephemeral_public)?;
    println!("Raw ECDH Bytes: {}", B64.encode(&ecdh_bytes));

    let (salt, hkdf_bytes) = crypto::hkdf(&ecdh_bytes)?;
    println!(
        "HKDF Enhanced Bits: {}.{}",
        B64.encode(salt),
        B64.encode(hkdf_bytes)
    );

    Ok(())
}
