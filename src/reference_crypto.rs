use openssl::aes::{AesKey, unwrap_key, wrap_key};
use openssl::derive::Deriver;
use openssl::hash::MessageDigest;
use openssl::rand;
use openssl::sha::sha1;

pub(crate) const SALT_SIZE: usize = 8;

pub(crate) type CryptoResult<T> = Result<T, String>;

pub(crate) fn ecdh(encryptor: &PKey<Private>, decryptor: &PKey<Public>) -> CryptoResult<Vec<u8>> {
    let mut deriver = Deriver::new(encryptor).map_err(|err| {
        format!("unable to initialize EC shared codepoint deriver from private key: {err:?}")
    })?;

    deriver
        .set_peer(decryptor)
        .map_err(|err| format!("unable to set peer as part of the exchange: {err:?}"))?;

    deriver
        .derive_to_vec()
        .map_err(|err| format!("unable to calculate shared secret: {err:?}"))
}

pub(crate) fn generate_key() -> CryptoResult<PKey<Private>> {
    let group = ec_group()?;

    let ec_key =
        EcKey::generate(&group).map_err(|err| format!("unable to generate EC key: {err:?}"))?;

    let private_key: PKey<Private> = ec_key
        .try_into()
        .map_err(|err| format!("failed to convert EC key into PKey: {err:?}"))?;

    Ok(private_key)
}

pub(crate) fn hkdf(derived_bits: &[u8], raw_salt: Option<[u8; SALT_SIZE]>) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let salt = match raw_salt {
        Some(s) => s,
        None => {
            let mut salt = [0u8; SALT_SIZE];
            rand::rand_bytes(&mut salt).map_err(|err| format!("unable to generate random IV: {err:?}"))?;
            salt
        }
    };

    // Note: this must be < 1024 chars and I should generate it base on other known data
    let info: &str = "fixed-data-todo";
    let mut hkdf_keys: [u8; 32] = [0; 32];

    openssl_hkdf::hkdf::hkdf(
        MessageDigest::sha256(),
        derived_bits,
        &salt,
        info.as_bytes(),
        &mut hkdf_keys,
    )
    .map_err(|err| format!("error calculating HKDF keys: {err:?}"))?;

    Ok((salt.to_vec(), hkdf_keys.to_vec()))
}

pub(crate) fn public_key(private_key: &PKey<Private>) -> CryptoResult<PKey<Public>> {
    let group = ec_group()?;

    let ec_key: EcKey<Private> = private_key
        .ec_key()
        .map_err(|err| format!("unable to get EC key from private key: {err:?}"))?;
    let pub_ec: EcKey<Public> =
        EcKey::from_public_key(&group, ec_key.public_key()).map_err(|err| {
            format!("unable to create public key from derived EC public key blocks: {err:?}")
        })?;

    PKey::from_ec_key(pub_ec)
        .map_err(|err| format!("unable to create public PKey from public EcKey: {err:?}"))
}

pub(crate) fn our_wrap_key(secret: &[u8], unprotected_key: &[u8]) -> CryptoResult<Vec<u8>> {
    let wrapping_key = AesKey::new_encrypt(secret)
        .map_err(|err| format!("unable to use secret for key wrapping: {err:?}"))?;

    let mut cipher_text = [0u8; 40];
    wrap_key(&wrapping_key, None, &mut cipher_text, &unprotected_key)
        .map_err(|err| format!("unable to wrap key: {err:?}"))?;

    Ok(cipher_text.to_vec())
}

pub(crate) fn our_unwrap_key(secret: &[u8], protected_key: &[u8]) -> CryptoResult<Vec<u8>> {
    let wrapping_key = AesKey::new_decrypt(secret)
        .map_err(|err| format!("unable to use secret for key unwrapping: {err:?}"))?;

    let mut plain_text = [0u8; 32];
    unwrap_key(&wrapping_key, None, &mut plain_text, &protected_key)
        .map_err(|err| format!("unable to wrap key: {err:?}"))?;

    Ok(plain_text.to_vec())
}
