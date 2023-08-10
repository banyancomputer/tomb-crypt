use async_trait::async_trait;
use openssl::pkey::{PKey, Public};

use crate::key_seal::common::*;
use crate::key_seal::native::*;
use crate::key_seal::TombCryptError;

pub struct EcPublicEncryptionKey(pub(crate) PKey<Public>);

#[async_trait(?Send)]
impl PublicKey for EcPublicEncryptionKey {
    type Error = TombCryptError;

    async fn export(&self) -> Result<Vec<u8>, TombCryptError> {
        self.0
            .public_key_to_pem()
            .map_err(TombCryptError::export_failed)
    }

    async fn export_bytes(&self) -> Result<Vec<u8>, TombCryptError> {
        self.0
            .public_key_to_der()
            .map_err(TombCryptError::export_failed)
    }

    async fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], TombCryptError> {
        Ok(internal::fingerprint(&self.0))
    }

    async fn import(pem_bytes: &[u8]) -> Result<Self, TombCryptError> {
        let raw_public =
            PKey::public_key_from_pem(pem_bytes).expect("parsing a valid pem public key");
        Ok(Self(raw_public))
    }

    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, TombCryptError> {
        let raw_public =
            PKey::public_key_from_der(der_bytes).expect("parsing a valid der public key");
        Ok(Self(raw_public))
    }
}
