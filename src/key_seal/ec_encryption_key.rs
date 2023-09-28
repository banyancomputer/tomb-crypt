use async_trait::async_trait;

use crate::key_seal::common::{PrivateKey, PublicKey, FINGERPRINT_SIZE};
use crate::key_seal::internal::{
    export_key_bytes, export_key_pem, gen_ec_key, import_key_bytes, import_key_pem,
};
use crate::key_seal::TombCryptError;
use crate::key_seal::{ec_key::EcKey, ec_public_key::EcPublicKey, EcPublicEncryptionKey};

pub struct EcEncryptionKey(pub(crate) EcKey);

#[async_trait(?Send)]
impl PrivateKey for EcEncryptionKey {
    type Error = TombCryptError;
    type PublicKey = EcPublicEncryptionKey;

    async fn export(&self) -> Result<Vec<u8>, TombCryptError> {
        self.0.export().await
    }

    async fn export_bytes(&self) -> Result<Vec<u8>, TombCryptError> {
        self.0.export_bytes().await
    }

    async fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], TombCryptError> {
        self.0.fingerprint().await
    }

    async fn generate() -> Result<Self, TombCryptError> {
        Ok(Self(EcKey(gen_ec_key())))
    }

    fn public_key(&self) -> Result<EcPublicEncryptionKey, TombCryptError> {
        Ok(EcPublicEncryptionKey(self.0.public_key()?))
    }

    async fn import(pem_bytes: &[u8]) -> Result<Self, TombCryptError> {
        Ok(Self(EcKey::import(pem_bytes).await?))
    }

    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, TombCryptError> {
        Ok(Self(EcKey::import_bytes(der_bytes).await?))
    }
}
