use std::collections::HashMap;

use pyramidion::prelude::*;

fn main() -> Result<(), KeySealError> {
    // This key is produced through normal WNFS operations
    let plaintext_temporal_key: &[u8; 32] = b"demo-key-do-not-reuse-sample-key";
    let temporal_key = SymmetricKey::from(*plaintext_temporal_key);

    // Create a new EC encryption key intended to be used to encrypt/decrypt temporal keys
    let our_device_key = EcEncryptionKey::generate()?;

    // Calculate a fingerprint of the device encryption key (works on public or private keys, will
    // produce the same response either way)
    let our_fingerprint = our_device_key.fingerprint()?;
    println!(
        "pretty printed version of our fingerprint: {}",
        pyramidion::pretty_fingerprint(&our_fingerprint)
    );

    // Just grab another public key for a fake other client, just to use as an example. We never
    // keep the private key ("this device doesn't have it").
    let other_device_key = EcEncryptionKey::generate()?.public_key()?;

    // Encryption can use any EC public key of the correct type, this public key should be
    // available in a standard format from elsewhere and is importable using
    // `EcPublicEncryptionKey::import`.
    let our_encrypted_temporal_key = temporal_key.encrypt_for(&our_device_key.public_key()?)?;

    // This is the common intermediate format that should be stored/exchanged
    let our_kex_blob = our_encrypted_temporal_key.export();

    // Also generate a friendly fingerprint for them
    let other_fingerprint = other_device_key.fingerprint()?;

    let other_encrypted_temporal_key = temporal_key.encrypt_for(&other_device_key)?;

    // This is the common intermediate format that should be stored/exchanged
    let other_kex_blob = other_encrypted_temporal_key.export();

    // Just an example of a simple key DB
    let mut shared_key_db = HashMap::new();
    shared_key_db.insert(our_fingerprint, our_kex_blob);
    shared_key_db.insert(other_fingerprint, other_kex_blob);
    println!("key_db contents: {shared_key_db:?}");

    // Retrieval of temporal key requires us to have our_device_key and the shared key database,
    // but nothing else.
    let stored_temporal_key = shared_key_db
        .get(&our_fingerprint)
        .expect("our key to still be present");

    // Retrieve this from some common / intermediate storage
    let loaded_temporal_key = EncryptedSymmetricKey::import(stored_temporal_key)?;

    // Decrypt the loaded key format (this will still be encrypted)
    let decrypted_temporal_key = loaded_temporal_key.decrypt_with(&our_device_key)?;

    // Extract the raw bytes for use elsewhere
    let mut raw_temporal_key = [0u8; 32];
    raw_temporal_key.copy_from_slice(decrypted_temporal_key.as_ref());

    // Sanity check
    assert_eq!(plaintext_temporal_key, &raw_temporal_key);

    Ok(())
}
