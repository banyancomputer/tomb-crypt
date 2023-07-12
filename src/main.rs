type CryptoResult<T> = Result<T, String>;

mod ec {
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use openssl::nid::Nid;
    use openssl::pkey::{HasPublic, PKey, Private, Public};

    use crate::CryptoResult;

    fn ec_group() -> CryptoResult<EcGroup> {
        EcGroup::from_curve_name(Nid::SECP384R1)
            .map_err(|err| format!("unable to lookup group curve name: {err:?}"))
    }

    pub(crate) fn generate_keypair() -> CryptoResult<(PKey<Private>, Vec<u8>)> {
        let group = ec_group()?;

        let ec_key =
            EcKey::generate(&group).map_err(|err| format!("unable to generate EC key: {err:?}"))?;

        let public_key = calculate_public_key(&ec_key)?;
        let private_key: PKey<Private> = ec_key
            .try_into()
            .map_err(|err| format!("failed to convert EC key into PKey: {err:?}"))?;

        Ok((private_key, public_key))
    }

    pub(crate) fn calculate_public_key<T>(private_key: &EcKey<T>) -> CryptoResult<Vec<u8>>
    where
        T: HasPublic,
    {
        let group = ec_group()?;

        let mut ctx = BigNumContext::new()
            .map_err(|err| format!("failed to create big num context: {err:?}"))?;

        private_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .map_err(|err| format!("unable to calculate public key: {err:?}"))
    }
}

fn main() -> CryptoResult<()> {
    let primary_pkey = ec::generate_keypair()?;
    let ephemeral_eckey = ec::generate_keypair()?;

    //let ephemeral_pkey: openssl::pkey::PKey<_> = match ephemeral_eckey.try_into() {
    //    Ok(pk) => pk,
    //    Err(err) => {
    //        println!("unable to convert eckey to pkey??? {err:?}");
    //        return Ok(());
    //    }
    //};

    //let mut deriver = match openssl::derive::Deriver::new(&ephemeral_pkey) {
    //    Ok(d) => d,
    //    Err(err) => {
    //        println!("unable to initialize deriver: {err:?}");
    //        return Ok(());
    //    }
    //};

    //if let Err(err) = deriver.set_peer(&primary_pkey) {
    //    println!("unable to set peer as part of the exchange: {err:?}");
    //    return Ok(());
    //}

    //let secret = match deriver.derive_to_vec() {
    //    Ok(s) => s,
    //    Err(err) => {
    //        println!("unable to calculate shared secret: {err:?}");
    //        return Ok(());
    //    }
    //};

    //println!("calculated secret: {secret:?}");

    Ok(())
}
