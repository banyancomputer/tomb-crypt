fn main() {
    let group = match openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1) {
        Ok(g) => g,
        Err(err) => {
            println!("unable to lookup group curve name: {err:?}");
            return;
        }
    };

    let primary_pkey: openssl::pkey::PKey<_> = match openssl::ec::EcKey::generate(&group) {
        Ok(eck) => match eck.try_into() {
            Ok(pk) => pk,
            Err(err) => {
                println!("unable to convert eckey to pkey??? {err:?}");
                return;
            }
        },
        Err(err) => {
            println!("unable to generate private key: {err:?}");
            return;
        }
    };

    let ephemeral_eckey = match openssl::ec::EcKey::generate(&group) {
        Ok(eck) => eck,
        Err(err) => {
            println!("unable to generate ephemeral key: {err:?}");
            return;
        }
    };

    let _ephemeral_public = {
        let mut ctx = match openssl::bn::BigNumContext::new() {
            Ok(c) => c,
            Err(err) => {
                println!("failed to create big num context: {err:?}");
                return;
            }
        };

        match ephemeral_eckey.public_key().to_bytes(
            &group,
            openssl::ec::PointConversionForm::COMPRESSED,
            &mut ctx,
        ) {
            Ok(pubkey) => pubkey,
            Err(err) => {
                println!("unable to calculate ephemeral public key: {err:?}");
                return;
            }
        }
    };

    let ephemeral_pkey: openssl::pkey::PKey<_> = match ephemeral_eckey.try_into() {
        Ok(pk) => pk,
        Err(err) => {
            println!("unable to convert eckey to pkey??? {err:?}");
            return;
        }
    };

    let mut deriver = match openssl::derive::Deriver::new(&ephemeral_pkey) {
        Ok(d) => d,
        Err(err) => {
            println!("unable to initialize deriver: {err:?}");
            return;
        }
    };

    if let Err(err) = deriver.set_peer(&primary_pkey) {
        println!("unable to set peer as part of the exchange: {err:?}");
        return;
    }

    let secret = match deriver.derive_to_vec() {
        Ok(s) => s,
        Err(err) => {
            println!("unable to calculate shared secret: {err:?}");
            return;
        }
    };

    println!("calculated secret: {secret:?}");
}
