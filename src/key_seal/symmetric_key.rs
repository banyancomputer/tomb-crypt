use async_trait::async_trait;

use crate::key_seal::common::{PlainKey, PrivateKey, PublicKey, AES_KEY_SIZE, SALT_SIZE};
use crate::key_seal::internal::{export_public_key_bytes, fingerprint, generate_salt};
use crate::key_seal::{generate_info, TombCryptError};
use crate::key_seal::{EcPublicEncryptionKey, EncryptedSymmetricKey};

use aes_gcm::{aead::Aead, AeadCore, AeadInPlace, Aes256Gcm, Key, KeyInit};
use hkdf::Hkdf;
use p384::elliptic_curve::ecdh::{diffie_hellman, EphemeralSecret};
use sha2;

#[derive(Debug)]
pub struct SymmetricKey(pub(crate) [u8; AES_KEY_SIZE]);

#[async_trait(?Send)]
impl PlainKey for SymmetricKey {
    type Error = TombCryptError;
    type ProtectedKey = EncryptedSymmetricKey;
    type PublicKey = EcPublicEncryptionKey;

    async fn encrypt_for(
        &self,
        recipient_key: &Self::PublicKey,
    ) -> Result<Self::ProtectedKey, TombCryptError> {
        let mut rng = rand::thread_rng();
        let ephemeral_secret = EphemeralSecret::random(&mut rng);
        let ephemeral_public_key = ephemeral_secret.public_key();
        let ephemeral_public_key_bytes = export_public_key_bytes(&ephemeral_public_key)?;
        println!(
            "ephemeral_public_key_bytes: {:?}",
            ephemeral_public_key_bytes
        );
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_key.0 .0);
        println!("shared secret");
        // Generate a random salt [u8
        let salt = generate_salt();
        // Generate a key from the shared secret and the salt
        let hkdf = shared_secret.extract::<sha2::Sha256>(Some(&salt));
        let mut key = [0u8; AES_KEY_SIZE];
        let info = generate_info(
            &fingerprint(&ephemeral_secret.public_key()),
            &fingerprint(&recipient_key.0 .0),
        );
        hkdf.expand(info.as_bytes(), &mut key).map_err(|e| {
            println!("hkdf.expand failed: {:?}", e);
            TombCryptError::hkdf_extract_failed(e)
        })?;

        let aes_key: &Key<Aes256Gcm> = &key.into();
        // Assert this is AES_KEY_SIZE bytes
        // assert_eq!(aes_key.as_ref().len(), AES_KEY_SIZE);
        let nonce = Aes256Gcm::generate_nonce(&mut rng);
        let cipher = Aes256Gcm::new(aes_key);
        // let mut enciphered_key: Vec<u8> = Vec::new();
        let cipher_text = cipher.encrypt(&nonce, self.0.as_ref()).map_err(|e| {
            println!("cipher.encrypt failed: {:?}", e);
            TombCryptError::encryption_failed(e)
        })?;
        Ok(EncryptedSymmetricKey {
            data: cipher_text.as_slice().try_into().unwrap(),
            salt,
            nonce: nonce.as_slice().try_into().unwrap(),
            public_key: ephemeral_public_key_bytes,
        })
    }
}

impl AsRef<[u8]> for SymmetricKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; AES_KEY_SIZE]> for SymmetricKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
