// use async_trait::async_trait;

// use crate::key_seal::common::*;
// use crate::key_seal::EcPublicSignatureKey;
// use crate::key_seal::EcSignatureKey;
// use crate::key_seal::KeySealError;
// use crate::pretty_fingerprint;
// use jwt_simple::prelude::*;

// #[derive(Debug, Serialize, Deserialize)]
// pub struct JsonWebToken(pub(crate) JWTClaims<NoCustomClaims>);

// impl JsonWebToken {
   
// #[async_trait(?Send)]
// impl ApiToken for JsonWebToken {
//     type Error = KeySealError;
//     type ApiPublicKey = EcPublicSignatureKey;
//     type ApiPrivateKey = EcSignatureKey;
//     // Parse the string as a token to verify
//     async fn decode_from(
//         token: &str,
//         public_key: &Self::ApiPublicKey,
//     ) -> Result<Self, Self::Error> {
//         let key_bytes = public_key.export_bytes().await?;
//         let key_id = pretty_fingerprint(&public_key.fingerprint().await?);
//         let decoding_key = ES384PublicKey::from_der(&key_bytes)
//             .map_err(KeySealError::jwt_error)?
//             .with_key_id(&key_id);

//         let token = decoding_key
//             .verify_token::<NoCustomClaims>(token, None)
//             .map_err(KeySealError::jwt_error)?;

//         Ok(Self(token))
//     }

//     // Parse the string as an encoded token
//     async fn encode(&self, signing_key: &Self::ApiPrivateKey) -> Result<String, Self::Error> {
//         let key_bytes = signing_key.export_bytes().await?;
//         let key_id = pretty_fingerprint(&signing_key.fingerprint().await?);
//         let encoding_key = ES384KeyPair::from_der(&key_bytes)
//             .map_err(KeySealError::jwt_error)?
//             .with_key_id(&key_id);
//         let claims = &self.0;
//         let token = encoding_key
//             .sign::<NoCustomClaims>(claims.clone())
//             .map_err(KeySealError::jwt_error)?;
//         Ok(token)
//     }
// }
