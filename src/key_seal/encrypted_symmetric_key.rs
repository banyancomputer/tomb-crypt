use async_trait::async_trait;

use crate::key_seal::common::{PrivateKey, ProtectedKey, PublicKey, AES_KEY_SIZE, SALT_SIZE};
use crate::key_seal::generate_info;
use crate::key_seal::internal::fingerprint;
use crate::key_seal::TombCryptError;
use crate::key_seal::{EcEncryptionKey, EcPublicEncryptionKey, SymmetricKey};
use crate::prelude::NONCE_SIZE;

use aes_gcm::{aead::Aead, AeadCore, AeadInPlace, Aes256Gcm, Key, KeyInit, Nonce};
use base64ct::{Base64, Decoder, Encoding};
use hkdf::Hkdf;
use p384::elliptic_curve::ecdh::{diffie_hellman, EphemeralSecret};
use sha2;

#[derive(Debug)]
pub struct EncryptedSymmetricKey {
    // TODO: is this the right size?
    pub(crate) salt: [u8; SALT_SIZE],
    pub(crate) nonce: [u8; NONCE_SIZE],
    pub(crate) data: [u8; AES_KEY_SIZE + 16],
    pub(crate) public_key: Vec<u8>,
}

#[async_trait(?Send)]
impl ProtectedKey for EncryptedSymmetricKey {
    type Error = TombCryptError;
    type PlainKey = SymmetricKey;
    type PrivateKey = EcEncryptionKey;

    async fn decrypt_with(
        &self,
        recipient_key: &EcEncryptionKey,
    ) -> Result<SymmetricKey, TombCryptError> {
        let ephemeral_public_key =
            EcPublicEncryptionKey::import_bytes(self.public_key.as_ref()).await?;
        // let shared_secret = recipient_key.0.0.diffie_hellman(&ephemeral_public_key.0.0);
        let shared_secret = diffie_hellman(
            &recipient_key.0 .0.to_nonzero_scalar(),
            ephemeral_public_key.0 .0.as_affine(),
        );
        let hkdf = shared_secret.extract::<sha2::Sha256>(Some(&self.salt));
        let mut key = [0u8; AES_KEY_SIZE];
        let info = generate_info(
            &fingerprint(&ephemeral_public_key.0 .0),
            &fingerprint(&recipient_key.public_key()?.0 .0),
        );
        hkdf.expand(info.as_bytes(), &mut key)
            .map_err(TombCryptError::hkdf_extract_failed)?;
        let aes_key: &Key<Aes256Gcm> = &key.into();
        let cipher = Aes256Gcm::new(aes_key);
        let plaintext_key = cipher
            .decrypt((&self.nonce).into(), self.data.as_ref())
            .map_err(TombCryptError::decryption_failed)?;
        let mut key = [0u8; AES_KEY_SIZE];
        key.copy_from_slice(&plaintext_key[..AES_KEY_SIZE]);
        Ok(SymmetricKey(key))
    }

    fn export(&self) -> String {
        [
            Base64::encode_string(&self.salt),
            Base64::encode_string(&self.nonce),
            Base64::encode_string(&self.data),
            Base64::encode_string(&self.public_key),
        ]
        .join(".")
    }

    fn import(serialized: &str) -> Result<Self, TombCryptError> {
        let components: Vec<_> = serialized.split('.').collect();

        // let raw_salt = Base64::decode(components[0], Encoding::Standard)?;
        let mut salt = [0u8; SALT_SIZE];
        Decoder::<Base64>::new(components[0].as_bytes())
            .unwrap()
            .decode(salt.as_mut())
            .unwrap();

        let mut nonce = [0u8; NONCE_SIZE];
        Decoder::<Base64>::new(components[1].as_bytes())
            .unwrap()
            .decode(nonce.as_mut())
            .unwrap();

        let mut data = [0u8; AES_KEY_SIZE + 16];
        Decoder::<Base64>::new(components[2].as_bytes())
            .unwrap()
            .decode(data.as_mut())
            .unwrap();

        let mut public_key = [0u8; 120];
        Decoder::<Base64>::new(components[3].as_bytes())
            .unwrap()
            .decode(public_key.as_mut())
            .unwrap();
        let public_key = public_key.to_vec();

        Ok(Self {
            salt,
            nonce,
            data,
            public_key,
        })
    }
}
