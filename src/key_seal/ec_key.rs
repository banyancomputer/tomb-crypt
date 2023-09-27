use async_trait::async_trait;

use crate::key_seal::traits::{PrivateKey, PublicKey, FINGERPRINT_SIZE};
use crate::key_seal::internal::{
    export_key_bytes, export_key_pem, gen_ec_key, import_key_bytes, import_key_pem,
};
use crate::key_seal::ec_public_key::EcPublicKey;
use crate::key_seal::TombCryptError;

use p384::SecretKey as P384SecretKey;

#[derive(Clone, Debug)]
pub struct EcKey(pub(crate) P384SecretKey);

#[async_trait(?Send)]
impl PrivateKey for EcKey {
    type Error = TombCryptError;
    type PublicKey = EcPublicKey;

    async fn export(&self) -> Result<Vec<u8>, TombCryptError> {
        export_key_pem(&self.0)
    }

    async fn export_bytes(&self) -> Result<Vec<u8>, TombCryptError> {
        export_key_bytes(&self.0)
    }

    async fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], TombCryptError> {
        self.public_key()?.fingerprint().await
    }

    async fn generate() -> Result<Self, TombCryptError> {
        Ok(Self(gen_ec_key()))
    }

    async fn import(pem_bytes: &[u8]) -> Result<Self, TombCryptError> {
        Ok(Self(import_key_pem(pem_bytes)?))
    }

    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, TombCryptError> {
        Ok(Self(import_key_bytes(der_bytes)?))
    }

    fn public_key(&self) -> Result<EcPublicKey, TombCryptError> {
        let p384_public_key = self.0.public_key();
        Ok(EcPublicKey(p384_public_key))
    }
}
