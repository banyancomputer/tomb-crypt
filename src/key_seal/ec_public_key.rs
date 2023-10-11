use std::sync::Arc;

use async_trait::async_trait;

use crate::key_seal::common::{PublicKey, FINGERPRINT_SIZE};
use crate::key_seal::internal::{
    export_public_key_bytes, export_public_key_pem, fingerprint, import_public_key_bytes,
    import_public_key_pem,
};
use crate::key_seal::TombCryptError;

use p384::PublicKey as P384PublicKey;

#[derive(Clone, Debug)]
pub struct EcPublicKey(pub(crate) P384PublicKey);

#[async_trait]
impl PublicKey for EcPublicKey {
    type Error = TombCryptError;

    async fn export(&self) -> Result<Vec<u8>, TombCryptError> {
        export_public_key_pem(&self.0)
    }

    async fn export_bytes(&self) -> Result<Vec<u8>, TombCryptError> {
        export_public_key_bytes(&self.0)
    }

    async fn fingerprint(&self) -> Result<Arc<[u8; FINGERPRINT_SIZE]>, TombCryptError> {
        Ok(Arc::new(fingerprint(&self.0)))
    }

    async fn import(pem_bytes: &[u8]) -> Result<Self, TombCryptError> {
        Ok(Self(import_public_key_pem(pem_bytes)?))
    }
    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, TombCryptError> {
        Ok(Self(import_public_key_bytes(der_bytes)?))
    }
}
