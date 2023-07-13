use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};

use crate::crypto::FINGERPRINT_SIZE;

fn ec_group() -> EcGroup {
    EcGroup::from_curve_name(Nid::SECP384R1).expect("selected EC group to remain valid")
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
