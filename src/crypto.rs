use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::rand;
use openssl::sha::sha1;

const SALT_SIZE: usize = 8;

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

fn ec_group() -> CryptoResult<EcGroup> {
    EcGroup::from_curve_name(Nid::SECP384R1)
        .map_err(|err| format!("unable to lookup group curve name: {err:?}"))
}

pub(crate) fn export_private_key(private_key: &PKey<Private>) -> CryptoResult<String> {
    let bytes = private_key
        .private_key_to_pem_pkcs8()
        .map_err(|err| format!("unable to export private key to pem: {err:?}"))?;

    String::from_utf8(bytes)
        .map_err(|err| format!("unable to convert pem bytes into a UTF8 string: {err:?}"))
}

pub(crate) fn export_public_key(public_key: &PKey<Public>) -> CryptoResult<String> {
    let bytes = public_key
        .public_key_to_pem()
        .map_err(|err| format!("unable to export private key to pem: {err:?}"))?;

    String::from_utf8(bytes)
        .map_err(|err| format!("unable to convert pem bytes into a UTF8 string: {err:?}"))
}

pub(crate) fn fingerprint(public_key: &PKey<Public>) -> CryptoResult<String> {
    let group = ec_group()?;
    let mut big_num_ctx =
        BigNumContext::new().map_err(|err| format!("unable to create big num context: {err:?}"))?;

    let ec_key: EcKey<Public> = public_key
        .ec_key()
        .map_err(|err| format!("unable to get EC key from public key: {err:?}"))?;

    let public_key_bytes = ec_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut big_num_ctx)
        .map_err(|err| format!("unable to extract public key bytes for fingerprint: {err:?}"))?;

    let fingerprint_bytes = sha1(&public_key_bytes);
    let fingerprint = fingerprint_bytes
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<String>>()
        .join(":");

    Ok(fingerprint)
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

pub(crate) fn hkdf(derived_bits: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];
    rand::rand_bytes(&mut salt).map_err(|err| format!("unable to generate random IV: {err:?}"))?;

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
