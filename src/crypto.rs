use openssl::pkey::{PKey, Private, Public};

mod internal;

const AES_KEY_SIZE: usize = 32;
const SALT_SIZE: usize = 16;

pub struct EcEncryptionKey(PKey<Private>);

impl EcEncryptionKey {
    pub fn import(pem_bytes: &[u8]) -> Self {
        todo!()
    }

    pub fn export(&self) -> Vec<u8> {
        todo!()
    }

    pub fn generate() -> Self {
        Self(internal::generate_ec_key())
    }

    pub fn public_key(&self) -> EcPublicEncryptionKey {
        todo!()
    }
}

pub struct EcPublicEncryptionKey(PKey<Public>);

impl EcPublicEncryptionKey {
    pub fn export(&self) -> Vec<u8> {
        todo!()
    }

    pub fn import(pem_bytes: &[u8]) -> Self {
        todo!()
    }
}

pub struct EncryptedTemporalKey {
    seed: [u8; SALT_SIZE],
    data: [u8; AES_KEY_SIZE + 8],
    public_key_pem: String,
}

impl EncryptedTemporalKey {
    pub fn decrypt_with(&self, recipient_key: &EcEncryptionKey) -> TemporalKey {
        todo!()
    }
}

pub struct TemporalKey([u8; AES_KEY_SIZE]);

impl TemporalKey {
    pub fn encrypt_for(&self, recipient_key: &EcPublicEncryptionKey) -> EncryptedTemporalKey {
        todo!()
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
