use async_trait::async_trait;

use crate::key_seal::common::{PublicKey, FINGERPRINT_SIZE};
use crate::key_seal::ec_public_key::EcPublicKey;
use crate::prelude::TombCryptError;

pub struct EcPublicEncryptionKey(pub(crate) EcPublicKey);

#[async_trait(?Send)]
impl PublicKey for EcPublicEncryptionKey {
    type Error = TombCryptError;

    async fn export(&self) -> Result<Vec<u8>, TombCryptError> {
        self.0.export().await
    }

    async fn export_bytes(&self) -> Result<Vec<u8>, TombCryptError> {
        self.0.export_bytes().await
    }

    async fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], TombCryptError> {
        self.0.fingerprint().await
    }

    async fn import(pem_bytes: &[u8]) -> Result<Self, TombCryptError> {
        Ok(Self(EcPublicKey::import(pem_bytes).await?))
    }

    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, TombCryptError> {
        Ok(Self(EcPublicKey::import_bytes(der_bytes).await?))
    }
}
// use async_trait::async_trait;
// use std::str::FromStr;
//
// use crate::key_seal::traits::{PublicKey, FINGERPRINT_SIZE};
// use crate::key_seal::internal::{
//     export_public_key_bytes, export_public_key_pem, fingerprint, import_public_key_bytes,
//     import_public_key_pem,
// };
// use crate::key_seal::TombCryptError;
//
// use p384::PublicKey as P384PublicKey;
// use sha1::Digest;
//
// #[derive(Clone, Debug)]
// pub struct EcPublicEncryptionKey(pub(crate) P384PublicKey);
//
// #[async_trait(?Send)]
// impl PublicKey for EcPublicEncryptionKey {
//     type Error = TombCryptError;
//
//     async fn export(&self) -> Result<Vec<u8>, TombCryptError> {
//         export_public_key_pem(&self.0)
//     }
//
//     async fn export_bytes(&self) -> Result<Vec<u8>, TombCryptError> {
//         export_public_key_bytes(&self.0)
//     }
//
//     async fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], TombCryptError> {
//         Ok(fingerprint(&self.0))
//     }
//
//     async fn import(pem_bytes: &[u8]) -> Result<Self, TombCryptError> {
//         Ok(Self(import_public_key_pem(pem_bytes)?))
//     }
//     async fn import_bytes(der_bytes: &[u8]) -> Result<Self, TombCryptError> {
//         Ok(Self(import_public_key_bytes(der_bytes)?))
//     }
// }
