use openssl::ec::EcGroup;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};

fn ec_group() -> EcGroup {
    EcGroup::from_curve_name(Nid::SECP384R1)
        .expect("selected EC group to remain valid")
}

pub(super) fn generate_ec_key() -> PKey<Private> {
    let ec_group = ec_group();

    todo!()
}
