type CryptoResult<T> = Result<T, String>;

mod ec {
    use openssl::bn::BigNumContext;
    use openssl::derive::Deriver;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private, Public};
    use openssl::sha::sha1;

    use crate::CryptoResult;

    pub(crate) fn ecdh(
        encryptor: &PKey<Private>,
        decryptor: &PKey<Public>,
    ) -> CryptoResult<Vec<u8>> {
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
        let mut big_num_ctx = BigNumContext::new()
            .map_err(|err| format!("unable to create big num context: {err:?}"))?;

        let ec_key: EcKey<Public> = public_key
            .ec_key()
            .map_err(|err| format!("unable to get EC key from public key: {err:?}"))?;

        let public_key_bytes = ec_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut big_num_ctx)
            .map_err(|err| {
                format!("unable to extract public key bytes for fingerprint: {err:?}")
            })?;

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
}

fn main() -> CryptoResult<()> {
    let primary_private = ec::generate_key()?;
    let primary_public = ec::public_key(&primary_private)?;

    let primary_private_pem = ec::export_private_key(&primary_private)?;
    let primary_public_pem = ec::export_public_key(&primary_public)?;
    println!(
        "Alice's Keys (Fingerprint: {}):\n{primary_private_pem}{primary_public_pem}",
        ec::fingerprint(&primary_public)?
    );

    let ephemeral_private = ec::generate_key()?;
    let ephemeral_public = ec::public_key(&ephemeral_private)?;

    let ephemeral_private_pem = ec::export_private_key(&ephemeral_private)?;
    let ephemeral_public_pem = ec::export_public_key(&ephemeral_public)?;
    println!(
        "Bob's Keys (Fingerprint: {}):\n{ephemeral_private_pem}{ephemeral_public_pem}",
        ec::fingerprint(&ephemeral_public)?
    );

    let secret_code_point = ec::ecdh(&primary_private, &ephemeral_public)?;
    println!("Raw ECDH Bytes: {}", base64::encode(&secret_code_point));

    Ok(())
}
