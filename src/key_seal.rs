pub mod common;

mod ec_encryption_key;
mod ec_key;
mod ec_public_encryption_key;
mod ec_public_key;
mod ec_public_signature_key;
mod ec_signature_key;
mod encrypted_symmetric_key;
mod error;
mod internal;
mod symmetric_key;
#[cfg(target_arch = "wasm32")]
pub mod wasm_helpers;

pub use ec_encryption_key::EcEncryptionKey;
pub use ec_public_encryption_key::EcPublicEncryptionKey;
pub use ec_public_signature_key::EcPublicSignatureKey;
pub use ec_signature_key::EcSignatureKey;
pub use encrypted_symmetric_key::EncryptedSymmetricKey;
pub use error::TombCryptError;
pub use symmetric_key::SymmetricKey;
#[cfg(target_arch = "wasm32")]
pub use wasm_helpers::*;

pub fn generate_info(encrypt_fingerprint_bytes: &[u8], decrypt_fingerprint_bytes: &[u8]) -> String {
    format!(
        "use=key_seal,encryptor={},decryptor={}",
        pretty_fingerprint(encrypt_fingerprint_bytes),
        pretty_fingerprint(decrypt_fingerprint_bytes),
    )
}

pub fn pretty_fingerprint(fingerprint_bytes: &[u8]) -> String {
    fingerprint_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<String>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    const PLAINTEXT_SYMMETRIC_KEY: &[u8; 32] = b"demo-key-do-not-reuse-sample-key";

    const TEST_PEM_KEY: &[u8] = &[
        45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45,
        45, 45, 45, 45, 10, 77, 73, 71, 50, 65, 103, 69, 65, 77, 66, 65, 71, 66, 121, 113, 71, 83,
        77, 52, 57, 65, 103, 69, 71, 66, 83, 117, 66, 66, 65, 65, 105, 66, 73, 71, 101, 77, 73, 71,
        98, 65, 103, 69, 66, 66, 68, 67, 78, 101, 114, 100, 114, 74, 76, 104, 85, 89, 49, 81, 79,
        81, 116, 85, 50, 10, 108, 54, 86, 118, 113, 55, 90, 108, 89, 66, 43, 97, 52, 56, 114, 88,
        43, 47, 111, 119, 122, 43, 69, 68, 103, 75, 118, 74, 114, 99, 111, 82, 114, 54, 117, 50,
        121, 78, 50, 87, 53, 119, 102, 51, 119, 68, 109, 104, 90, 65, 78, 105, 65, 65, 84, 109, 66,
        57, 99, 69, 53, 54, 105, 57, 10, 89, 88, 70, 106, 107, 85, 54, 122, 73, 100, 98, 97, 118,
        83, 102, 102, 117, 115, 112, 119, 98, 114, 71, 104, 102, 80, 122, 103, 106, 77, 82, 43, 71,
        98, 65, 77, 103, 57, 116, 84, 78, 102, 99, 121, 122, 81, 55, 66, 86, 99, 106, 97, 102, 90,
        114, 84, 56, 90, 75, 87, 85, 82, 74, 68, 10, 73, 112, 67, 76, 119, 102, 89, 106, 66, 52,
        98, 89, 107, 100, 87, 85, 115, 121, 82, 101, 88, 53, 121, 79, 73, 100, 74, 88, 80, 112, 50,
        82, 100, 106, 68, 118, 80, 82, 116, 67, 117, 76, 67, 117, 76, 72, 57, 88, 52, 116, 122,
        100, 47, 65, 107, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 82, 73, 86, 65, 84, 69,
        32, 75, 69, 89, 45, 45, 45, 45, 45, 10,
    ];

    const TEST_DER_KEY: &[u8] = &[
        48, 129, 155, 2, 1, 1, 4, 48, 141, 122, 183, 107, 36, 184, 84, 99, 84, 14, 66, 213, 54,
        151, 165, 111, 171, 182, 101, 96, 31, 154, 227, 202, 215, 251, 250, 48, 207, 225, 3, 128,
        171, 201, 173, 202, 17, 175, 171, 182, 200, 221, 150, 231, 7, 247, 192, 57, 161, 100, 3,
        98, 0, 4, 230, 7, 215, 4, 231, 168, 189, 97, 113, 99, 145, 78, 179, 33, 214, 218, 189, 39,
        223, 186, 202, 112, 110, 177, 161, 124, 252, 224, 140, 196, 126, 25, 176, 12, 131, 219, 83,
        53, 247, 50, 205, 14, 193, 85, 200, 218, 125, 154, 211, 241, 146, 150, 81, 18, 67, 34, 144,
        139, 193, 246, 35, 7, 134, 216, 145, 213, 148, 179, 36, 94, 95, 156, 142, 33, 210, 87, 62,
        157, 145, 118, 48, 239, 61, 27, 66, 184, 176, 174, 44, 127, 87, 226, 220, 221, 252, 9,
    ];

    const SEALED_KEY: &str = "gWpi+A3+mAm9IaeeI1Fq+g==./7hxZHDThkpnUr58.zLfay5f24Ou/gpXeTn/UTdTLO2vf/65U8hk70Xt6aWTO4gPKmfEdXeDwfIR+q1hX.MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEJR9Nd3p/UA8UPut9wRt+r7mx5Fv9wxopA+B5gm0lyFSzhJRZO6D4x57sJ68YiDvxSUfSCaOhWWhYTRJ6WxShf/g0bdLdkPrtxelSKHcUj3orr9rELWYUl1fxE6kOfSS4";

    // async fn generate_constants() -> Result<(), TombCryptError> {
    //     use crate::key_seal::common::PrivateKey;
    //     let private_key = EcEncryptionKey::generate().await?;
    //     println!("PEM: {:?}", private_key.export().await?);
    //     println!("DER: {:?}", private_key.export_bytes().await?);

    //     let public_key = private_key.public_key()?;
    //     let symmetric_key: SymmetricKey = (*PLAINTEXT_SYMMETRIC_KEY).into();
    //     let encrypted_symmetric_key = symmetric_key.encrypt_for(&public_key).await?;
    //     println!("encrypted_symmetric: {}", encrypted_symmetric_key.export());
    //     Ok(())
    // }

    async fn test_encryption_end_to_end() -> Result<(), TombCryptError> {
        use crate::key_seal::common::PrivateKey;

        let temporal_key = SymmetricKey::from(*PLAINTEXT_SYMMETRIC_KEY);

        let device_key = EcEncryptionKey::generate().await?;
        let encrypted_temporal_key = temporal_key.encrypt_for(&device_key.public_key()?).await?;
        let kex_blob = encrypted_temporal_key.export();
        let loaded_temporal_key = EncryptedSymmetricKey::import(&kex_blob)?;
        let decrypted_temporal_key = loaded_temporal_key.decrypt_with(&device_key).await?;

        let mut raw_temporal_key = [0u8; 32];
        raw_temporal_key.copy_from_slice(decrypted_temporal_key.as_ref());

        assert_eq!(PLAINTEXT_SYMMETRIC_KEY, &raw_temporal_key);

        Ok(())
    }

    async fn test_encryption_key_roundtripping() -> Result<(), TombCryptError> {
        use crate::key_seal::common::{PrivateKey, PublicKey};
        let key = EcEncryptionKey::generate().await?;
        let public_key = key.public_key()?;

        // dirty comparisons but works for now
        let raw_key_bytes = key.export_bytes().await?;
        let imported_key = EcEncryptionKey::import_bytes(&raw_key_bytes).await?;
        let reexported_key_bytes = imported_key.export_bytes().await?;
        assert_eq!(raw_key_bytes, reexported_key_bytes);
        let raw_public_key_bytes = public_key.export_bytes().await?;
        let imported_public_key =
            EcPublicEncryptionKey::import_bytes(&raw_public_key_bytes).await?;
        let reexported_public_key_bytes = imported_public_key.export_bytes().await?;
        assert_eq!(raw_public_key_bytes, reexported_public_key_bytes);

        let raw_key_pem = key.export().await?;
        let imported_key = EcEncryptionKey::import(&raw_key_pem).await?;
        let reexported_key_pem = imported_key.export().await?;
        assert_eq!(raw_key_pem, reexported_key_pem);

        let raw_public_key_pem = public_key.export().await?;
        let imported_public_key = EcPublicEncryptionKey::import(&raw_public_key_pem).await?;
        let reexported_public_key_pem = imported_public_key.export().await?;
        assert_eq!(raw_public_key_pem, reexported_public_key_pem);

        Ok(())
    }

    async fn test_signature_key_roundtripping() -> Result<(), TombCryptError> {
        use crate::key_seal::common::{PrivateKey, PublicKey};

        let key = EcSignatureKey::generate().await?;
        let public_key = key.public_key()?;

        // dirty comparisons but works for now
        let raw_key_bytes = key.export_bytes().await?;
        let imported_key = EcSignatureKey::import_bytes(&raw_key_bytes).await?;
        let reexported_key_bytes = imported_key.export_bytes().await?;
        assert_eq!(raw_key_bytes, reexported_key_bytes);

        let raw_public_key_bytes = public_key.export_bytes().await?;
        let imported_public_key = EcPublicSignatureKey::import_bytes(&raw_public_key_bytes).await?;
        let reexported_public_key_bytes = imported_public_key.export_bytes().await?;
        assert_eq!(raw_public_key_bytes, reexported_public_key_bytes);

        let raw_key_pem = key.export().await?;
        let imported_key = EcSignatureKey::import(&raw_key_pem).await?;
        let reexported_key_pem = imported_key.export().await?;
        assert_eq!(raw_key_pem, reexported_key_pem);

        let raw_public_key_pem = public_key.export().await?;
        let imported_public_key = EcPublicSignatureKey::import(&raw_public_key_pem).await?;
        let reexported_public_key_pem = imported_public_key.export().await?;
        assert_eq!(raw_public_key_pem, reexported_public_key_pem);

        Ok(())
    }

    async fn test_api_token() -> Result<(), TombCryptError> {
        use crate::key_seal::common::{ApiToken, ApiTokenMetadata, PrivateKey, PublicKey};
        let key = EcSignatureKey::generate().await?;
        let public_key = key.public_key()?;

        let claims = ApiToken::new("test".to_string(), "test".to_string());
        let token = claims.encode_to(&key).await?;
        let _ = ApiToken::decode_from(&token, &public_key).await?;
        let metadata = ApiTokenMetadata::try_from(token)?;
        let key_id = pretty_fingerprint(public_key.fingerprint().await?.as_slice());

        // Check the metadata
        assert_eq!(metadata.alg(), "ES384");
        assert_eq!(metadata.kid()?, key_id);
        assert_eq!(metadata.typ()?, "JWT");

        // Check the claims
        assert!(!claims.is_expired()?);
        assert!(claims.iat()? < claims.exp()?);
        assert!(claims.nbf()? < claims.exp()?);
        assert_eq!(claims.aud()?, "test");
        assert_eq!(claims.sub()?, "test");

        Ok(())
    }

    async fn test_api_token_fail() -> Result<(), TombCryptError> {
        use crate::key_seal::common::{ApiToken, PrivateKey};
        let key = EcSignatureKey::generate().await?;
        let bad_key = EcSignatureKey::generate().await?;
        let bad_public_key = bad_key.public_key()?;

        let claims = ApiToken::new("test".to_string(), "test".to_string());
        let token = claims.encode_to(&key).await?;
        let _ = ApiToken::decode_from(&token, &bad_public_key).await?;

        Ok(())
    }

    async fn test_pem_key_parse_and_use() -> Result<(), TombCryptError> {
        use crate::key_seal::common::PrivateKey;
        let private_key = EcEncryptionKey::import(TEST_PEM_KEY).await?;
        let protected_key = EncryptedSymmetricKey::import(SEALED_KEY)?;
        let plain_key = protected_key.decrypt_with(&private_key).await?;
        assert_eq!(plain_key.as_ref(), PLAINTEXT_SYMMETRIC_KEY);
        Ok(())
    }

    async fn test_der_key_parse_and_use() -> Result<(), TombCryptError> {
        use crate::key_seal::common::PrivateKey;

        let private_key = EcEncryptionKey::import_bytes(TEST_DER_KEY).await?;
        let protected_key = EncryptedSymmetricKey::import(SEALED_KEY)?;
        let plain_key = protected_key.decrypt_with(&private_key).await?;
        assert_eq!(plain_key.as_ref(), PLAINTEXT_SYMMETRIC_KEY);

        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native_tests {
        use super::*;

        #[tokio::test]
        async fn pem_key_parse_and_use() -> Result<(), TombCryptError> {
            test_pem_key_parse_and_use().await
        }

        #[tokio::test]
        async fn der_key_parse_and_use() -> Result<(), TombCryptError> {
            test_der_key_parse_and_use().await
        }

        #[tokio::test]
        async fn encryption_end_to_end() -> Result<(), TombCryptError> {
            test_encryption_end_to_end().await
        }

        #[tokio::test]
        async fn encryption_key_roundtripping() -> Result<(), TombCryptError> {
            test_encryption_key_roundtripping().await
        }

        #[tokio::test]
        async fn signature_key_roundtripping() -> Result<(), TombCryptError> {
            test_signature_key_roundtripping().await
        }

        #[tokio::test]
        async fn api_token() -> Result<(), TombCryptError> {
            test_api_token().await
        }

        #[tokio::test]
        #[should_panic]
        async fn api_token_fail() {
            test_api_token_fail().await.unwrap();
        }
    }

    #[cfg(target_arch = "wasm32")]
    mod wasm_tests {
        use super::*;
        use wasm_bindgen_test::*;

        wasm_bindgen_test_configure!(run_in_browser);

        #[wasm_bindgen_test]
        async fn pem_key_parse_and_use() -> Result<(), TombCryptError> {
            test_pem_key_parse_and_use().await
        }

        #[wasm_bindgen_test]
        async fn der_key_parse_and_use() -> Result<(), TombCryptError> {
            test_der_key_parse_and_use().await
        }

        #[wasm_bindgen_test]
        async fn encryption_end_to_end() -> Result<(), TombCryptError> {
            test_encryption_end_to_end().await
        }

        #[wasm_bindgen_test]
        async fn encryption_key_roundtripping() -> Result<(), TombCryptError> {
            test_encryption_key_roundtripping().await
        }

        #[wasm_bindgen_test]
        async fn signature_key_roundtripping() -> Result<(), TombCryptError> {
            test_signature_key_roundtripping().await
        }

        #[wasm_bindgen_test]
        async fn api_token() -> Result<(), TombCryptError> {
            test_api_token().await
        }

        #[wasm_bindgen_test]
        #[should_panic]
        async fn api_token_fail() -> Result<(), TombCryptError> {
            test_api_token_fail().await
        }
    }
}
