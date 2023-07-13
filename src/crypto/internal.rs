use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};

use crate::crypto::{AES_KEY_SIZE, FINGERPRINT_SIZE, SALT_SIZE};

const ECDH_SECRET_BYTE_SIZE: usize = 48;

pub(crate) fn base64_decode(data: &str) -> Vec<u8> {
    B64.decode(data).expect("data to be valid base64")
}

pub(crate) fn base64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

fn ec_group() -> EcGroup {
    EcGroup::from_curve_name(Nid::SECP384R1).expect("selected EC group to remain valid")
}

pub(crate) fn ecdh_exchange(
    private: &PKey<Private>,
    public: &PKey<Public>,
) -> [u8; ECDH_SECRET_BYTE_SIZE] {
    todo!()
}

pub(crate) fn fingerprint(public_key: &PKey<Public>) -> [u8; FINGERPRINT_SIZE] {
    let ec_group = ec_group();
    let mut big_num_context = BigNumContext::new().expect("BigNumContext creation");

    let ec_public_key = public_key.ec_key().expect("key to be an EC derived key");

    let public_key_bytes = ec_public_key
        .public_key()
        .to_bytes(
            &ec_group,
            PointConversionForm::COMPRESSED,
            &mut big_num_context,
        )
        .expect("generate public key bytes");

    openssl::sha::sha1(&public_key_bytes)
}

pub(crate) fn generate_ec_key() -> PKey<Private> {
    let ec_group = ec_group();

    todo!()
}

pub(crate) fn hkdf(secret_bytes: &[u8]) -> ([u8; SALT_SIZE], [u8; AES_KEY_SIZE]) {
    todo!()
}

pub(crate) fn hkdf_with_salt(secret_bytes: &[u8], salt: &[u8]) -> [u8; AES_KEY_SIZE] {
    todo!()
}

pub(crate) fn public_from_private(private_key: &PKey<Private>) -> PKey<Public> {
    todo!()
}

pub(crate) fn unwrap_key(secret_bytes: &[u8], protected_key: &[u8]) -> [u8; AES_KEY_SIZE] {
    todo!()
}

pub(crate) fn wrap_key(secret_bytes: &[u8], unprotected_key: &[u8]) -> [u8; AES_KEY_SIZE + 8] {
    todo!()
}
