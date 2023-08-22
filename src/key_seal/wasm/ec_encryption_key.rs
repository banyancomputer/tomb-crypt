use async_trait::async_trait;
use web_sys::{CryptoKey, CryptoKeyPair};

use crate::key_seal::common::{PrivateKey, PublicKey, FINGERPRINT_SIZE};
use crate::key_seal::wasm::internal::{EcKeyExportFormat, EcKeyType};
use crate::key_seal::wasm::*;
use crate::key_seal::TombCryptError;

#[derive(Clone, Debug)]
pub struct EcEncryptionKey {
    pub(crate) private_key: CryptoKey,
    pub(crate) public_key: Option<CryptoKey>,
}

impl EcEncryptionKey {
    pub fn with_public_key(mut self, public_key: CryptoKey) -> Self {
        self.public_key = Some(public_key);
        self
    }
}

#[async_trait(?Send)]
impl PrivateKey for EcEncryptionKey {
    type Error = TombCryptError;
    type PublicKey = EcPublicEncryptionKey;

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
        let key_pair = internal::generate_ec_key_pair(EcKeyType::Encryption)
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
            internal::import_ec_key_pem(EcKeyExportFormat::Pkcs8, pem_bytes, EcKeyType::Encryption)
                .await
                .map_err(TombCryptError::bad_format)?;
        Ok(Self {
            private_key,
            public_key: None,
        })
    }

    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, TombCryptError> {
        let private_key =
            internal::import_ec_key_der(EcKeyExportFormat::Pkcs8, der_bytes, EcKeyType::Encryption)
                .await
                .map_err(TombCryptError::bad_format)?;
        Ok(Self {
            private_key,
            public_key: None,
        })
    }

    fn public_key(&self) -> Result<EcPublicEncryptionKey, TombCryptError> {
        let public_key = self
            .public_key
            .as_ref()
            .ok_or(TombCryptError::public_key_unavailable())?;
        Ok(EcPublicEncryptionKey(public_key.clone()))
    }
}

impl From<CryptoKey> for EcEncryptionKey {
    fn from(private_key: CryptoKey) -> Self {
        Self {
            private_key,
            public_key: None,
        }
    }
}

impl From<CryptoKeyPair> for EcEncryptionKey {
    fn from(key_pair: CryptoKeyPair) -> Self {
        Self {
            private_key: internal::private_key(&key_pair),
            public_key: Some(internal::public_key(&key_pair)),
        }
    }
}

impl From<EcEncryptionKey> for CryptoKey {
    fn from(key: EcEncryptionKey) -> Self {
        key.private_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn from_crypto_key() -> Result<(), TombCryptError> {
        let key_pair = internal::generate_ec_key_pair(EcKeyType::Encryption)
            .await
            .unwrap();
        let private_key = internal::private_key(&key_pair);
        let ec_encryption_key = EcEncryptionKey::from(private_key);
        assert_eq!(ec_encryption_key.public_key, None);
        assert_eq!(
            ec_encryption_key.private_key,
            internal::private_key(&key_pair)
        );
        Ok(())
    }
}
