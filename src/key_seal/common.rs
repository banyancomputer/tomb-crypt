use async_trait::async_trait;
use jwt_simple::prelude::*;
use std::error::Error;

use crate::prelude::*;
use crate::pretty_fingerprint;

/// Number of bytes used for our AES keys (256-bit)
pub const AES_KEY_SIZE: usize = 32;

/// Length of a negotiated key exchange using our select EC curve (P384). It is assumed other
/// algorithms with different key lengths aren't going to be used.
pub const ECDH_SECRET_BYTE_SIZE: usize = 48;

/// Number of bytes present in an unformatted fingerprint.
pub const FINGERPRINT_SIZE: usize = 20;

/// Number of bytes used for our salts and IVs
pub const SALT_SIZE: usize = 16;

/// The number of seconds JWTs are valid for
pub const JWT_DURATION: u64 = 870;

/// A WrappingPrivateKey is an opinionated cryptographic type designed for encrypting and
/// decrypting (wrapping) a symmetric AES key using an EC group key.
#[async_trait(?Send)]
pub trait WrappingPrivateKey: Sized {
    /// The error type that will commonly be returned by all concrete implementations of the type.
    type Error: Error;

    /// This is the type that will constitute the public portion of this concrete implementation.
    type PublicKey: WrappingPublicKey<Error = Self::Error>;

    /// Converts the private key representation into a PEM wrapped PKCS8 private key. The returned
    /// bytes should all be printable UTF8 characters which can be turned into a string on demand.
    ///
    /// This format should be preferred if the data is going to be visible to people or platforms
    /// as it is immediately recognizable.
    async fn export(&self) -> Result<Vec<u8>, Self::Error>;

    /// Export the internal private key into a DER encoded set of bytes.
    async fn export_bytes(&self) -> Result<Vec<u8>, Self::Error>;

    /// Create a standards compliant SHA1 fingerprint of the associated public key encoded as a
    /// fixed length bytes string. This is usually presented to users by running it through the
    /// prettifier [`crate::key_seal::pretty_fingerprint()`].
    async fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], Self::Error> {
        self.public_key()?.fingerprint().await
    }

    /// Creates a secure new private key matching the security and use requirements for use as a EC
    /// wrapping key.
    async fn generate() -> Result<Self, Self::Error>;

    /// Parses a PEM encoded EC private key into the internal type appropriate for being used as a
    /// wrapping key.
    async fn import(pem_bytes: &[u8]) -> Result<Self, Self::Error>;

    /// Parses a DER encoded EC private key into the internal type appropriate for being used as a
    /// wrapping key.
    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, Self::Error>;

    fn public_key(&self) -> Result<Self::PublicKey, Self::Error>;
}

/// The public portion of a [`WrappingPrivateKey`]. The public portion is important for tracking
/// the identity of the keys and can be used to encrypt any plain key in a way the holder the
/// private key can get access to.
#[async_trait(?Send)]
pub trait WrappingPublicKey: Sized {
    /// The error type that will commonly be returned by all concrete implementations of the type.
    type Error: Error;

    /// Converts the public portion of the wrapping key into a PEM/SPKI formatted version that is
    /// easy to exchange in a visibly identifiable way and works over ASCII only channels.
    async fn export(&self) -> Result<Vec<u8>, Self::Error>;

    /// Exports the public portion of a private key as a DER formatted byte string. Preferred when
    /// exchanging and embedding in formats that will already be encoded using other means.
    async fn export_bytes(&self) -> Result<Vec<u8>, Self::Error>;

    /// Generates a SHA1 over the standardized compressed form representation of an EC key. This is
    /// usually presented to users by running it through the prettifier
    /// [`crate::key_seal::pretty_fingerprint()`].
    async fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], Self::Error>;

    /// IMPORT A STANDARD PEM FORMATTED VERSION OF AN EC KEY.
    async fn import(pem_bytes: &[u8]) -> Result<Self, Self::Error>;

    /// Import a standard DER formatted EC key byte string
    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, Self::Error>;
}

/// An ApiKey is a key that is used to sign API requests to the server.
#[async_trait(?Send)]
pub trait ApiPrivateKey: Sized {
    /// The error type that will commonly be returned by all concrete implementations of the type.
    type Error: Error;

    /// This is the type that will constitute the public portion of this concrete implementation.
    type PublicKey: ApiPublicKey<Error = Self::Error>;

    /// Converts the private key representation into a PEM wrapped PKCS8 private key. The returned
    /// bytes should all be printable UTF8 characters which can be turned into a string on demand.
    ///
    /// This format should be preferred if the data is going to be visible to people or platforms
    /// as it is immediately recognizable.
    async fn export(&self) -> Result<Vec<u8>, Self::Error>;

    /// Export the internal private key into a DER encoded set of bytes.
    async fn export_bytes(&self) -> Result<Vec<u8>, Self::Error>;

    /// Create a standards compliant SHA1 fingerprint of the associated public key encoded as a
    /// fixed length bytes string. This is usually presented to users by running it through the
    /// prettifier [`crate::key_seal::pretty_fingerprint()`].
    async fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], Self::Error> {
        self.public_key()?.fingerprint().await
    }

    /// Creates a secure new private key matching the security and use requirements for use as a EC
    /// wrapping key.
    async fn generate() -> Result<Self, Self::Error>;

    /// Parses a PEM encoded EC private key into the internal type appropriate for being used as a
    /// wrapping key.
    async fn import(pem_bytes: &[u8]) -> Result<Self, Self::Error>;

    /// Parses a DER encoded EC private key into the internal type appropriate for being used as a
    /// wrapping key.
    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, Self::Error>;

    fn public_key(&self) -> Result<Self::PublicKey, Self::Error>;
}

/// The public portion of an ApiKey. This is the portion that is used to verify the signature of JWTs.
#[async_trait(?Send)]
pub trait ApiPublicKey: Sized {
    /// The error type that will commonly be returned by all concrete implementations of the type.
    type Error: Error;

    /// Converts the public portion of the api key into a PEM/SPKI formatted version that is
    /// easy to exchange in a visibly identifiable way and works over ASCII only channels.
    async fn export(&self) -> Result<Vec<u8>, Self::Error>;

    /// Exports the public portion of a private key as a DER formatted byte string. Preferred when
    /// exchanging and embedding in formats that will already be encoded using other means.
    async fn export_bytes(&self) -> Result<Vec<u8>, Self::Error>;

    /// Generates a SHA1 over the standardized compressed form representation of an EC key. This is
    /// usually presented to users by running it through the prettifier
    /// [`crate::key_seal::pretty_fingerprint()`].
    async fn fingerprint(&self) -> Result<[u8; FINGERPRINT_SIZE], Self::Error>;

    /// IMPORT A STANDARD PEM FORMATTED VERSION OF AN EC KEY.
    async fn import(pem_bytes: &[u8]) -> Result<Self, Self::Error>;

    /// Import a standard DER formatted EC key byte string
    async fn import_bytes(der_bytes: &[u8]) -> Result<Self, Self::Error>;
}

/// A wrapper around an unprotected 256-bit AES key. The raw key can act as a raw byte string for
/// other implementation to use for encryption and decryption.
#[async_trait(?Send)]
pub trait PlainKey: AsRef<[u8]> + From<[u8; AES_KEY_SIZE]> {
    /// The error type that will commonly be returned by all concrete implementations of the type.
    type Error: Error;

    /// The type the key will have once it has been protected with public key
    type ProtectedKey: ProtectedKey;

    /// This is the concrete implementation of the public portion of an EC key used to encrypt this
    /// key for a specific individual.
    type WrappingPublicKey: WrappingPublicKey;

    /// Wrap the internal plaintext key with the provided public key. Only the holder of the
    /// private portion will be able to reconstruct the original key.
    async fn encrypt_for(
        &self,
        recipient_key: &Self::WrappingPublicKey,
    ) -> Result<Self::ProtectedKey, Self::Error>;
}

/// A wrapped key and the associated deta required to decrypt the data into the original key when
/// provided with an appropriate private key.
#[async_trait(?Send)]
pub trait ProtectedKey: Sized {
    /// The error type that will commonly be returned by all concrete implementations of the type.
    type Error: Error;

    /// The decrypted key type that will be produced by providing the correct private key.
    type PlainKey: PlainKey;

    /// The concrete implementation of a private key that is capable of decrypting this protected
    /// key.
    type WrappingPrivateKey: WrappingPrivateKey;

    /// Attempts to decrypt the protected key with the provided private key, if successful this
    /// will produce a plaintext key.
    async fn decrypt_with(
        &self,
        recipient_key: &Self::WrappingPrivateKey,
    ) -> Result<Self::PlainKey, Self::Error>;

    /// Export the protected key into a standardized format that can be exchanged freely.
    fn export(&self) -> String;

    /// Import protected key from the standardized format
    fn import(serialized: &str) -> Result<Self, Self::Error>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiToken(pub(crate) JWTClaims<NoCustomClaims>);

impl ApiToken {
    /// Create a new token
    /// # Arguments
    /// * `audience` - The audience for the token
    /// * `subject` - The subject for the token
    /// # Returns
    /// A new JsonWebToken
    pub fn new(audience: String, subject: String) -> Self {
        Self(
            Claims::create(Duration::from_secs(JWT_DURATION))
                .with_audience(audience)
                .with_subject(subject),
        )
    }

    // Parse the string as a token to verify
    pub async fn decode_from<'a, E>(
        token: &str,
        public_key: impl ApiPublicKey<Error = E>,
    ) -> Result<Self, Box<dyn std::error::Error + 'a>>
    where
        E: std::error::Error + 'a,
    {
        let key_bytes = public_key.export_bytes().await?;
        let key_id = pretty_fingerprint(&public_key.fingerprint().await?);
        let decoding_key = ES384PublicKey::from_der(&key_bytes)
            .map_err(KeySealError::jwt_error)?
            .with_key_id(&key_id);

        let token = decoding_key
            .verify_token::<NoCustomClaims>(token, None)
            .map_err(KeySealError::jwt_error)?;

        Ok(Self(token))
    }

    // Parse the string as an encoded token
    pub async fn encode<'a, E>(
        &self,
        signing_key: impl ApiPrivateKey<Error = E>,
    ) -> Result<String, Box<dyn std::error::Error + 'a>>
    where
        E: std::error::Error + 'a,
    {
        let key_bytes = signing_key.export_bytes().await?;
        let key_id = pretty_fingerprint(&signing_key.fingerprint().await?);
        let encoding_key = ES384KeyPair::from_der(&key_bytes)
            .map_err(KeySealError::jwt_error)?
            .with_key_id(&key_id);
        let claims = &self.0;
        let token = encoding_key
            .sign::<NoCustomClaims>(claims.clone())
            .map_err(KeySealError::jwt_error)?;
        Ok(token)
    }
}

// /// A wrapper trait around a JWT token that can be used to authenticate API requests.
// #[async_trait(?Send)]
// pub trait ApiToken: Sized {
//     /// The error type that will commonly be returned by all concrete implementations of the type.
//     type Error: Error;

//     /// The concrete implementation of a private key that is capable of decrypting this protected
//     /// key.
//     type ApiPrivateKey: ApiPrivateKey;

//     /// The concrete implementation of a private key that is capable of decrypting this protected
//     /// key.
//     type ApiPublicKey: ApiPublicKey;

//     /// Attempts to decode the JWT with the provided public key. Errors if the signature is invalid
//     async fn decode_from(token: &str, sender_key: &Self::ApiPublicKey)
//         -> Result<Self, Self::Error>;

//     /// Attempts to encode the JWT with the provided private key.
//     async fn encode(&self, sender_key: &Self::ApiPrivateKey) -> Result<String, Self::Error>;
// }
