use async_trait::async_trait;

use crate::key_seal::traits::{PlainKey, PrivateKey, PublicKey, AES_KEY_SIZE, SALT_SIZE};
use crate::key_seal::internal::{fingerprint, generate_salt};
use crate::key_seal::{EcPublicEncryptionKey, EncryptedSymmetricKey};
use crate::key_seal::{generate_info, TombCryptError};

use hkdf::Hkdf;
use p384::elliptic_curve::ecdh::{diffie_hellman, EphemeralSecret};
use sha2;

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
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_key.0.0);
        // Generate a random salt [u8
        let salt = generate_salt();
        // Generate a key from the shared secret and the salt
        let hkdf = shared_secret.extract::<sha2::Sha256>(Some(&salt));
        let mut key = [0u8; AES_KEY_SIZE];
        let info = generate_info(
            &fingerprint(&ephemeral_secret.public_key()),
            &fingerprint(&recipient_key.0.0),
        );
        hkdf.expand(info.as_bytes(), &mut key)
            .map_err(|_| TombCryptError::secret_sharing_failed())?;
        panic!("Not implemented");
        //
        // let encrypted_key = internal::wrap_key(&hkdf_shared_secret, &self.0);
        // let exported_ephemeral_key = ephemeral_key.public_key()?.export_bytes().await?;
        //
        // Ok(EncryptedSymmetricKey {
        //     data: encrypted_key,
        //     salt,
        //     public_key: exported_ephemeral_key,
        // })
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
