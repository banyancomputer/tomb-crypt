use async_trait::async_trait;

use crate::key_seal::common::{PrivateKey, FINGERPRINT_SIZE};
use crate::key_seal::{ec_key::EcKey, EcPublicSignatureKey};

use crate::key_seal::TombCryptError;

pub struct EcSignatureKey(pub(crate) EcKey);

#[async_trait(?Send)]
impl PrivateKey for EcSignatureKey {
    type Error = TombCryptError;
    type PublicKey = EcPublicSignatureKey;

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
        Ok(Self(EcKey::generate().await?))
    }

    async fn import(pem_bytes: &[u8]) -> Result<Self, TombCryptError> {
        Ok(Self(EcKey::import(pem_bytes).await?))
    }

    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, TombCryptError> {
        Ok(Self(EcKey::import_bytes(der_bytes).await?))
    }

    fn public_key(&self) -> Result<EcPublicSignatureKey, TombCryptError> {
        Ok(EcPublicSignatureKey(self.0.public_key()?))
    }
}
