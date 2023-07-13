use std::fmt::{self, Display, Formatter};

use openssl::pkey::{PKey, Private, Public};

mod internal;

const AES_KEY_SIZE: usize = 32;
const FINGERPRINT_SIZE: usize = 20;
const SALT_SIZE: usize = 16;

pub struct EcEncryptionKey(PKey<Private>);

impl EcEncryptionKey {
    pub fn export(&self) -> Vec<u8> {
        self.0
            .private_key_to_pem_pkcs8()
            .expect("unable to export private key to pem")
    }

    pub fn fingerprint(&self) -> [u8; FINGERPRINT_SIZE] {
        self.public_key().fingerprint()
    }

    pub fn generate() -> Self {
        Self(internal::generate_ec_key())
    }

    pub fn import(pem_bytes: &[u8]) -> Self {
        todo!()
    }

    pub fn public_key(&self) -> EcPublicEncryptionKey {
        let ec_public = internal::public_from_private(&self.0);
        EcPublicEncryptionKey(ec_public)
    }
}

pub struct EcPublicEncryptionKey(PKey<Public>);

impl EcPublicEncryptionKey {
    pub fn export(&self) -> Vec<u8> {
        self.0
            .public_key_to_pem()
            .expect("unable to export public key to pem")
    }

    pub fn fingerprint(&self) -> [u8; FINGERPRINT_SIZE] {
        internal::fingerprint(&self.0)
    }

    pub fn import(pem_bytes: &[u8]) -> Self {
        todo!()
    }
}

pub struct EncryptedTemporalKey {
    data: [u8; AES_KEY_SIZE + 8],
    salt: [u8; SALT_SIZE],
    public_key_pem: Vec<u8>,
}

impl EncryptedTemporalKey {
    pub fn decrypt_with(&self, recipient_key: &EcEncryptionKey) -> TemporalKey {
        let ephemeral_public_key = EcPublicEncryptionKey::import(self.public_key_pem.as_ref());
        let ecdh_shared_secret = internal::ecdh_exchange(&recipient_key.0, &ephemeral_public_key.0);
        let hkdf_shared_secret = internal::hkdf_with_salt(&ecdh_shared_secret, self.salt.as_ref());

        let temporal_key_bytes = internal::unwrap_key(&hkdf_shared_secret, self.data.as_ref());

        TemporalKey(temporal_key_bytes)
    }
}

impl Display for EncryptedTemporalKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}",
            internal::base64_encode(&self.salt),
            internal::base64_encode(&self.data),
            internal::base64_encode(self.public_key_pem.as_ref())
        )
    }
}

pub struct TemporalKey([u8; AES_KEY_SIZE]);

impl TemporalKey {
    pub fn encrypt_for(&self, recipient_key: &EcPublicEncryptionKey) -> EncryptedTemporalKey {
        let ephemeral_key = EcEncryptionKey::generate();

        let ecdh_shared_secret = internal::ecdh_exchange(&ephemeral_key.0, &recipient_key.0);
        let (salt, hkdf_shared_secret) = internal::hkdf(&ecdh_shared_secret);
        let encrypted_key = internal::wrap_key(&hkdf_shared_secret, &self.0);

        let exported_ephemeral_key = ephemeral_key.public_key().export();

        EncryptedTemporalKey {
            data: encrypted_key,
            salt,
            public_key_pem: exported_ephemeral_key,
        }
    }

    #[cfg(test)]
    fn generate() -> Self {
        let mut key_data = [0u8; AES_KEY_SIZE];
        openssl::rand::rand_bytes(&mut key_data)
            .map_err(|err| format!("unable to generate key data: {err:?}"))?;
        Ok(Self(key_data))
    }
}

impl AsRef<[u8]> for TemporalKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; AES_KEY_SIZE]> for TemporalKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
