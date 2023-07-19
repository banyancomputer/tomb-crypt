use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use openssl::aes::{self, AesKey};
use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};

use crate::key_seal::{
    pretty_fingerprint, AES_KEY_SIZE, ECDH_SECRET_BYTE_SIZE, FINGERPRINT_SIZE, SALT_SIZE,
};

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
    let mut deriver =
        Deriver::new(private).expect("creation of ECDH derivation context from private key");
    deriver
        .set_peer(public)
        .expect("setting openssl peer for ECDH key derivation");

    let calculated_bytes = deriver
        .derive_to_vec()
        .expect("calculate common public key");

    let mut key_slice = [0u8; ECDH_SECRET_BYTE_SIZE];
    key_slice.copy_from_slice(&calculated_bytes);

    key_slice
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
    let ec_key = EcKey::generate(&ec_group).expect("EC key generation to succeed");
    ec_key
        .try_into()
        .expect("EC private key to be convertible to private key type")
}

pub(crate) fn generate_info(encryptor: &[u8], decryptor: &[u8]) -> String {
    format!(
        "use=key_seal,encryptor={},decryptor={}",
        pretty_fingerprint(encryptor),
        pretty_fingerprint(decryptor),
    )
}

pub(crate) fn hkdf(secret_bytes: &[u8], info: &str) -> ([u8; SALT_SIZE], [u8; AES_KEY_SIZE]) {
    let mut salt = [0u8; SALT_SIZE];
    openssl::rand::rand_bytes(&mut salt).expect("unable to generate random IV");
    (salt, hkdf_with_salt(secret_bytes, &salt, info))
}

pub(crate) fn hkdf_with_salt(secret_bytes: &[u8], salt: &[u8], info: &str) -> [u8; AES_KEY_SIZE] {
    let mut expanded_key = [0; AES_KEY_SIZE];

    openssl_hkdf::hkdf::hkdf(
        MessageDigest::sha256(),
        secret_bytes,
        salt,
        info.as_bytes(),
        &mut expanded_key,
    )
    .expect("hkdf operation to succeed");

    expanded_key
}

pub(crate) fn public_from_private(private_key: &PKey<Private>) -> PKey<Public> {
    let ec_group = ec_group();

    let ec_key = private_key
        .ec_key()
        .expect("unable to extract EC private key from private key");
    // Have to do a weird little dance here as to we need to temporarily go into bytes to get to a
    // public only key
    let pub_ec_key: EcKey<Public> = EcKey::from_public_key(&ec_group, ec_key.public_key())
        .expect("unable to turn public key bytes into public key");

    PKey::from_ec_key(pub_ec_key).expect("unable to wrap public key in common struct")
}

pub(crate) fn unwrap_key(secret_bytes: &[u8], protected_key: &[u8]) -> [u8; AES_KEY_SIZE] {
    let wrapping_key =
        AesKey::new_decrypt(secret_bytes).expect("use of secret bytes when unwrapping key");

    let mut plaintext_key = [0u8; AES_KEY_SIZE];
    aes::unwrap_key(&wrapping_key, None, &mut plaintext_key, protected_key)
        .expect("unwrapping to succeed");

    plaintext_key
}

pub(crate) fn wrap_key(secret_bytes: &[u8], unprotected_key: &[u8]) -> [u8; AES_KEY_SIZE + 8] {
    let wrapping_key =
        AesKey::new_encrypt(secret_bytes).expect("use of secret bytes when wrapping key");

    let mut enciphered_key = [0u8; AES_KEY_SIZE + 8];
    aes::wrap_key(&wrapping_key, None, &mut enciphered_key, unprotected_key)
        .expect("wrapping to succeed");

    enciphered_key
}