use base64ct::LineEnding;
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    PublicKey as P384PublicKey, SecretKey as P384SecretKey,
};
use rand::RngCore;
use sha1::Digest;

use crate::key_seal::common::{FINGERPRINT_SIZE, SALT_SIZE};
use crate::prelude::TombCryptError;

pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt: [u8; 16] = [0u8; SALT_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    salt
}

/// SHA1 compressed point fingerprint function
pub fn fingerprint<'a>(public_key: impl Into<&'a P384PublicKey>) -> [u8; FINGERPRINT_SIZE] {
    let public_key = public_key.into();
    let compressed_point = public_key.as_ref().to_encoded_point(true);

    let mut hasher = sha1::Sha1::new();
    hasher.update(compressed_point);
    let hashed_bytes = hasher.finalize();
    hashed_bytes.into()
}

// pub fn fingerprint<'a>(public_key: impl Into<&'a P384PublicKey>) -> [u8; FINGERPRINT_SIZE] {
//     let public_key = public_key.into();

//     let bytes = public_key.to_sec1_bytes();
//     let mut hasher = sha1::Sha1::new();
//     hasher.update(&bytes);
//     let bytes = hasher.finalize();
//     let bytes = bytes.as_slice();
//     let mut fingerprint = [0u8; FINGERPRINT_SIZE];
//     fingerprint.copy_from_slice(&bytes[..FINGERPRINT_SIZE]);
//     fingerprint
// }

pub fn gen_ec_key() -> P384SecretKey {
    let mut rng = rand::thread_rng();
    P384SecretKey::random(&mut rng)
}

pub fn import_key_bytes(der_bytes: &[u8]) -> Result<P384SecretKey, TombCryptError> {
    P384SecretKey::from_sec1_der(der_bytes)
        .map_err(|_| TombCryptError::private_key_import_bytes_failed())
}
pub fn export_key_bytes(private_key: &P384SecretKey) -> Result<Vec<u8>, TombCryptError> {
    Ok(private_key
        .to_sec1_der()
        .map_err(|_| TombCryptError::private_key_export_bytes_failed())?
        .to_vec())
}
pub fn import_key_pem(pem_bytes: &[u8]) -> Result<P384SecretKey, TombCryptError> {
    let pem_string = std::str::from_utf8(pem_bytes).map_err(TombCryptError::invalid_utf8)?;
    P384SecretKey::from_pkcs8_pem(pem_string).map_err(TombCryptError::private_key_import_failed)
}
pub fn export_key_pem(private_key: &P384SecretKey) -> Result<Vec<u8>, TombCryptError> {
    Ok(private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(TombCryptError::private_key_export_failed)?
        .as_bytes()
        .to_vec())
}
pub fn import_public_key_bytes(der_bytes: &[u8]) -> Result<P384PublicKey, TombCryptError> {
    P384PublicKey::from_public_key_der(der_bytes).map_err(TombCryptError::public_key_import_failed)
}
pub fn export_public_key_bytes(public_key: &P384PublicKey) -> Result<Vec<u8>, TombCryptError> {
    Ok(public_key
        .to_public_key_der()
        .map_err(TombCryptError::public_key_export_failed)?
        .into_vec())
}
pub fn import_public_key_pem(pem_bytes: &[u8]) -> Result<P384PublicKey, TombCryptError> {
    let pem_string = std::str::from_utf8(pem_bytes).map_err(TombCryptError::invalid_utf8)?;
    P384PublicKey::from_public_key_pem(pem_string).map_err(TombCryptError::public_key_import_failed)
}
pub fn export_public_key_pem(public_key: &P384PublicKey) -> Result<Vec<u8>, TombCryptError> {
    Ok(public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(TombCryptError::public_key_export_failed)?
        .as_bytes()
        .to_vec())
}
