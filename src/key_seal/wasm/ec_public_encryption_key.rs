use async_trait::async_trait;
use web_sys::CryptoKey;

use crate::key_seal::common::{PublicKey, FINGERPRINT_SIZE};
use crate::key_seal::wasm::internal::{EcKeyExportFormat, EcKeyType};
use crate::key_seal::wasm::*;
use crate::key_seal::TombCryptError;

#[derive(Clone, Debug)]
pub struct EcPublicEncryptionKey(pub(crate) CryptoKey);

#[async_trait(?Send)]
impl PublicKey for EcPublicEncryptionKey {
    type Error = TombCryptError;

    async fn export(&self) -> Result<Vec<u8>, TombCryptError> {
        internal::export_ec_key_pem(EcKeyExportFormat::Spki, &self.0)
            .await
            .map_err(TombCryptError::subtle_crypto_error)
    }

    async fn export_bytes(&self) -> Result<Vec<u8>, TombCryptError> {
        internal::export_ec_key_der(EcKeyExportFormat::Spki, &self.0)
            .await
            .map_err(TombCryptError::subtle_crypto_error)
    }

    async fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], TombCryptError> {
        Ok(internal::fingerprint_public_ec_key(&self.0)
            .await
            .map_err(TombCryptError::subtle_crypto_error)?)
    }

    async fn import(pem_bytes: &[u8]) -> Result<Self, TombCryptError> {
        let public_key =
            internal::import_ec_key_pem(EcKeyExportFormat::Spki, pem_bytes, EcKeyType::Encryption)
                .await
                .map_err(TombCryptError::subtle_crypto_error)?;
        Ok(Self(public_key))
    }

    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, TombCryptError> {
        let public_key =
            internal::import_ec_key_der(EcKeyExportFormat::Spki, der_bytes, EcKeyType::Encryption)
                .await
                .map_err(TombCryptError::subtle_crypto_error)?;
        Ok(Self(public_key))
    }
}

impl From<CryptoKey> for EcPublicEncryptionKey {
    fn from(public_key: CryptoKey) -> Self {
        Self(public_key)
    }
}
