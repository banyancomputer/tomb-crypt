use crate::key_seal::ec_public_key::EcPublicKey;
use crate::key_seal::{ec_key::EcKey, internal::*};
use crate::prelude::*;
use js_sys::{
    Array, ArrayBuffer, Error as JsError, JsString, Object, Promise, Reflect, Uint8Array,
};
use pem::{encode, parse, Pem};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    CryptoKey, CryptoKeyPair, EcKeyGenParams, EcdhKeyDeriveParams, HkdfParams, SubtleCrypto,
};

pub(crate) type JsResult<T> = Result<T, JsError>;

fn js_array(values: &[&str]) -> JsValue {
    return JsValue::from(
        values
            .iter()
            .map(|x| JsValue::from_str(x))
            .collect::<Array>(),
    );
}

/// Get the subtle crypto object from the window
pub(crate) fn subtle_crypto() -> JsResult<SubtleCrypto> {
    Ok(gloo::utils::window().crypto()?.subtle())
}

/// Run an Async function that returns a promise. Return as a Vec<u8>
async fn crypto_method(method: Result<Promise, JsValue>) -> JsResult<JsValue> {
    Ok(JsFuture::from(method?)
        .await
        .expect("crytpo method promise to succeed"))
}

fn get_private_key(key_pair: &CryptoKeyPair) -> CryptoKey {
    Reflect::get(key_pair, &JsString::from("privateKey"))
        .unwrap()
        .into()
}

fn get_public_key(key_pair: &CryptoKeyPair) -> CryptoKey {
    Reflect::get(key_pair, &JsString::from("publicKey"))
        .unwrap()
        .into()
}

#[derive(Clone, Copy)]
pub(crate) enum EcKeyType {
    Encryption,
    Signature,
}

pub(crate) enum EcKeyFormat {
    Pkcs8,
    Spki,
    Raw,
}

impl EcKeyFormat {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            EcKeyFormat::Pkcs8 => "pkcs8",
            EcKeyFormat::Spki => "spki",
            EcKeyFormat::Raw => "raw",
        }
    }
}

/// Return EcKeyGenParams for the given key type
pub(crate) fn ec_key_gen_params(key_type: EcKeyType) -> EcKeyGenParams {
    match key_type {
        EcKeyType::Encryption => EcKeyGenParams::new("ECDH", "P-384"),
        EcKeyType::Signature => EcKeyGenParams::new("ECDSA", "P-384"),
    }
}

// CryptoKeyPair -> EcEncryptionKey
// CryptoKeyPair -> EcSignatureKey
// CryptoKey -> PublicEncryptionKey

pub async fn key_pair_to_encryption_key(key_pair: &CryptoKeyPair) -> JsResult<EcEncryptionKey> {
    let pem_bytes = export_ec_key_pem(EcKeyFormat::Pkcs8, &get_private_key(key_pair)).await?;
    gloo::console::log!(format!(
        "key_pair_to_encryption_key pem bytes: {:?}",
        pem_bytes
    ));
    Ok(EcEncryptionKey(EcKey(
        import_key_pem(&pem_bytes).expect(""),
    )))
}

pub async fn key_pair_to_signature_key(key_pair: &CryptoKeyPair) -> JsResult<EcSignatureKey> {
    let pem_bytes = export_ec_key_pem(EcKeyFormat::Pkcs8, &get_private_key(key_pair)).await?;
    gloo::console::log!(format!(
        "key_pair_to_signature_key pem bytes: {:?}",
        pem_bytes
    ));
    Ok(EcSignatureKey(EcKey(import_key_pem(&pem_bytes).expect(""))))
}

pub async fn key_to_public_encryption_key(key: &CryptoKey) -> JsResult<EcPublicEncryptionKey> {
    let pem_bytes = export_ec_key_pem(EcKeyFormat::Spki, key).await?;
    Ok(EcPublicEncryptionKey(EcPublicKey(
        import_public_key_pem(&pem_bytes).expect(""),
    )))
}

/// Export a CryptoKey as DER bytes
pub async fn export_ec_key_der(format: EcKeyFormat, key: &CryptoKey) -> JsResult<Vec<u8>> {
    let crypto = subtle_crypto()?;
    let export = crypto_method(crypto.export_key(format.as_str(), key)).await?;
    let export = export
        .dyn_into::<ArrayBuffer>()
        .expect("export result to be an array buffer");
    let export = Uint8Array::new(&export).to_vec();
    Ok(export)
}

/// Export an ec key as a Vec<u8> in pem format
pub(crate) async fn export_ec_key_pem(
    format: EcKeyFormat,
    public_key: &CryptoKey,
) -> JsResult<Vec<u8>> {
    let tag: &str = match format {
        EcKeyFormat::Pkcs8 => "PRIVATE KEY",
        EcKeyFormat::Spki => "PUBLIC KEY",
        _ => panic!("invalid format"),
    };
    let key_contents = export_ec_key_der(format, public_key).await?;
    let pem = Pem::new(tag, key_contents);
    Ok(encode(&pem).as_bytes().to_vec())
}

/// Import DER bytes as a CryptoKey
pub async fn import_ec_key_der(
    format: EcKeyFormat,
    der_bytes: &[u8],
    key_type: EcKeyType,
) -> JsResult<CryptoKey> {
    let crypto = subtle_crypto()?;
    let params = ec_key_gen_params(key_type);
    let usages = match key_type.clone() {
        EcKeyType::Encryption => js_array(&["deriveBits"]),
        EcKeyType::Signature => match format {
            EcKeyFormat::Pkcs8 => js_array(&["sign"]),
            EcKeyFormat::Spki => js_array(&["verify"]),
            _ => panic!("invalid format"),
        },
    };
    let import = crypto_method(crypto.import_key_with_object(
        format.as_str(),
        &Uint8Array::from(der_bytes),
        &params,
        true,
        &usages,
    ))
    .await?;
    Ok(import.into())
}

/// Import an ec key from a &[u8] in pem format
pub(crate) async fn import_ec_key_pem(
    key_export_format: EcKeyFormat,
    public_key: &[u8],
    key_type: EcKeyType,
) -> JsResult<CryptoKey> {
    let pem = std::str::from_utf8(public_key).unwrap();
    let pem = parse(pem).unwrap();
    let contents = pem.contents();
    let import = import_ec_key_der(key_export_format, contents, key_type).await?;
    Ok(import)
}
