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
