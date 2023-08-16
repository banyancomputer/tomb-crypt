use async_trait::async_trait;
use web_sys::{CryptoKey, CryptoKeyPair};

use crate::key_seal::common::{PrivateKey, PublicKey, FINGERPRINT_SIZE};
use crate::key_seal::wasm::internal::{EcKeyExportFormat, EcKeyType};
use crate::key_seal::wasm::*;
use crate::key_seal::TombCryptError;

#[derive(Clone, Debug)]
pub struct EcSignatureKey {
    pub(crate) private_key: CryptoKey,
    pub(crate) public_key: Option<CryptoKey>,
}

#[async_trait(?Send)]
impl PrivateKey for EcSignatureKey {
    type Error = TombCryptError;
    type PublicKey = EcPublicSignatureKey;

    async fn export(&self) -> Result<Vec<u8>, TombCryptError> {
        internal::export_ec_key_pem(EcKeyExportFormat::Pkcs8, &self.private_key)
            .await
            .map_err(TombCryptError::export_failed)
    }

    async fn export_bytes(&self) -> Result<Vec<u8>, TombCryptError> {
        internal::export_ec_key_der(EcKeyExportFormat::Pkcs8, &self.private_key)
            .await
            .map_err(TombCryptError::export_failed)
    }

    async fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], TombCryptError> {
        self.public_key()?.fingerprint().await
    }

    async fn generate() -> Result<Self, TombCryptError> {
        let key_pair = internal::generate_ec_key_pair(EcKeyType::Signature)
            .await
            .map_err(TombCryptError::subtle_crypto_error)?;
        let private_key = internal::private_key(&key_pair);
        let public_key = internal::public_key(&key_pair);
        Ok(Self {
            private_key,
            public_key: Some(public_key),
        })
    }

    async fn import(pem_bytes: &[u8]) -> Result<Self, TombCryptError> {
        let private_key =
            internal::import_ec_key_pem(EcKeyExportFormat::Pkcs8, pem_bytes, EcKeyType::Signature)
                .await
                .map_err(TombCryptError::bad_format)?;
        Ok(Self {
            private_key,
            public_key: None,
        })
    }

    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, TombCryptError> {
        let private_key =
            internal::import_ec_key_der(EcKeyExportFormat::Pkcs8, der_bytes, EcKeyType::Signature)
                .await
                .map_err(TombCryptError::bad_format)?;
        Ok(Self {
            private_key,
            public_key: None,
        })
    }

    fn public_key(&self) -> Result<EcPublicSignatureKey, TombCryptError> {
        let public_key = self
            .public_key
            .as_ref()
            .ok_or(TombCryptError::public_key_unavailable())?;
        Ok(EcPublicSignatureKey(public_key.clone()))
    }
}

impl From<CryptoKey> for EcSignatureKey {
    fn from(private_key: CryptoKey) -> Self {
        Self {
            private_key,
            public_key: None,
        }
    }
}

impl From<CryptoKeyPair> for EcSignatureKey {
    fn from(key_pair: CryptoKeyPair) -> Self {
        Self {
            private_key: internal::private_key(&key_pair),
            public_key: Some(internal::public_key(&key_pair)),
        }
    }
}
