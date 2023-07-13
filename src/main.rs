use crypto_playground::prelude::*;

fn main() {
    // Create a new EC encryption key intended to be used to encrypt/decrypt temporal keys
    let device_encryption_key = EcEncryptionKey::generate();

    // This key is produced through normal WNFS operations
    let plaintext_temporal_key: &[u8; 32] = b"demo-key-do-not-reuse-sample-key";
    let temporal_key = TemporalKey::from(plaintext_temporal_key.clone());

    // Encryption can use any EC public key of the correct type, this public key should be
    // available in a standard format from elsewhere and is importable using
    // `EcPublicEncryptionKey::import`.
    let encrypted_temporal_key = temporal_key.encrypt_for(&device_encryption_key.public_key());

    // This is the common intermediate format that should be stored/exchanged
    let stored_temporal_key = encrypted_temporal_key.export();

    println!("exchange encrypted temporal key: {stored_temporal_key}");

    // Retrieve this from some common / intermediate storage
    let loaded_temporal_key = EncryptedTemporalKey::import(&stored_temporal_key);

    // Decrypt the loaded key format (this will still be encrypted)
    let decrypted_temporal_key = loaded_temporal_key.decrypt_with(&device_encryption_key);

    // Extract the raw bytes for use elsewhere
    let mut raw_temporal_key = [0u8; 32];
    raw_temporal_key.copy_from_slice(decrypted_temporal_key.as_ref());

    // Sanity check
    assert_eq!(plaintext_temporal_key, &raw_temporal_key);

    // Calculate a fingerprint of the device encryption key (works on public or private keys)
    let fingerprint = device_encryption_key.fingerprint();
    let friendly_fingerprint = crypto_playground::pretty_fingerprint(&fingerprint);

    println!("device fingerprint: {friendly_fingerprint}");
}
