//use base64::engine::general_purpose::STANDARD as B64;
//use base64::Engine;

use crypto_playground::prelude::*;

fn main() {
    //let primary_private = crypto::generate_key()?;
    //let primary_public = crypto::public_key(&primary_private)?;

    //let primary_private_pem = crypto::export_private_key(&primary_private)?;
    //let primary_public_pem = crypto::export_public_key(&primary_public)?;
    //println!(
    //    "Alice's Keys (Fingerprint: {}):\n{primary_private_pem}{primary_public_pem}",
    //    crypto::fingerprint(&primary_public)?
    //);

    //let ephemeral_private = crypto::generate_key()?;
    //let ephemeral_public = crypto::public_key(&ephemeral_private)?;

    //let ephemeral_private_pem = crypto::export_private_key(&ephemeral_private)?;
    //let ephemeral_public_pem = crypto::export_public_key(&ephemeral_public)?;
    //println!(
    //    "Bob's Keys (Fingerprint: {}):\n{ephemeral_private_pem}{ephemeral_public_pem}",
    //    crypto::fingerprint(&ephemeral_public)?
    //);

    //// First round

    //let ecdh_bytes = crypto::ecdh(&ephemeral_private, &primary_public)?;
    //println!("Raw ECDH Bytes: {}", B64.encode(&ecdh_bytes));

    //let (salt, hkdf_bytes) = crypto::hkdf(&ecdh_bytes, None)?;
    //println!(
    //    "HKDF Enhanced Bits: {}.{}",
    //    B64.encode(salt.as_slice()),
    //    B64.encode(hkdf_bytes.as_slice())
    //);

    //// These are the bytes that make up the WNFS temporal key, this value is used as a placeholder
    //const plaintext_temporal_key: &[u8; 32] = b"demo-key-do-not-reuse-sample-key";

    //let wrapped_key = crypto::our_wrap_key(hkdf_bytes.as_slice(), plaintext_temporal_key.as_ref())?;
    //println!("Wrapped Key: {}", B64.encode(&wrapped_key));

    //// Now lets try and recover from the other side

    //let recovered_ecdh_bytes = crypto::ecdh(&primary_private, &ephemeral_public)?;
    //assert_eq!(ecdh_bytes, recovered_ecdh_bytes, "derived keys to be the same");

    //let mut salt_bytes = [0u8; crypto::SALT_SIZE];
    //salt_bytes.copy_from_slice(salt.as_slice());
    //let (_, recovered_hkdf_bytes) = crypto::hkdf(&recovered_ecdh_bytes, Some(salt_bytes))?;

    //let unwrapped_key = crypto::our_unwrap_key(recovered_hkdf_bytes.as_slice(), wrapped_key.as_slice())?;
    //assert_eq!(plaintext_temporal_key, unwrapped_key.as_slice(), "unencrypted temporal key should be the same");

    //println!("Unwrapped Key: {}", String::from_utf8_lossy(unwrapped_key.as_slice()));

    let device_encryption_key = EcEncryptionKey::generate();

    // This key is produced through normal WNFS operations
    let plaintext_temporal_key: &[u8; 32] = b"demo-key-do-not-reuse-sample-key";
    let temporal_key = TemporalKey::from(plaintext_temporal_key.clone());

    // Encryption can use any EC public key of the correct type
    let encrypted_temporal_key = temporal_key.encrypt_for(&device_encryption_key.public_key());
    let decrypted_temporal_key = encrypted_temporal_key.decrypt_with(&device_encryption_key);

    let mut raw_temporal_key = [0u8; 32];
    raw_temporal_key.copy_from_slice(decrypted_temporal_key.as_ref());

    assert_eq!(plaintext_temporal_key, &raw_temporal_key);
}
