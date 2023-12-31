use std::sync::Arc;

use async_trait::async_trait;

use crate::key_seal::common::{PublicKey, FINGERPRINT_SIZE};
use crate::key_seal::ec_public_key::EcPublicKey;
use crate::key_seal::TombCryptError;

#[derive(Clone, Debug)]
pub struct EcPublicSignatureKey(pub(crate) EcPublicKey);

#[async_trait]
impl PublicKey for EcPublicSignatureKey {
    type Error = TombCryptError;

    async fn export(&self) -> Result<Vec<u8>, TombCryptError> {
        self.0.export().await
    }

    async fn export_bytes(&self) -> Result<Vec<u8>, TombCryptError> {
        self.0.export_bytes().await
    }

    async fn fingerprint(&self) -> Result<Arc<[u8; FINGERPRINT_SIZE]>, TombCryptError> {
        self.0.fingerprint().await
    }

    async fn import(pem_bytes: &[u8]) -> Result<Self, TombCryptError> {
        Ok(Self(EcPublicKey::import(pem_bytes).await?))
    }

    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, TombCryptError> {
        Ok(Self(EcPublicKey::import_bytes(der_bytes).await?))
    }
}
