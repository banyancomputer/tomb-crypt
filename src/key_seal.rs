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

pub use ec_encryption_key::EcEncryptionKey;
pub use ec_public_encryption_key::EcPublicEncryptionKey;
pub use ec_public_signature_key::EcPublicSignatureKey;
pub use ec_signature_key::EcSignatureKey;
pub use encrypted_symmetric_key::EncryptedSymmetricKey;
pub use error::TombCryptError;
pub use symmetric_key::SymmetricKey;

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
        98, 65, 103, 69, 66, 66, 68, 66, 112, 75, 52, 54, 112, 107, 121, 113, 81, 51, 72, 112, 66,
        122, 48, 75, 71, 10, 49, 119, 55, 89, 112, 85, 83, 43, 68, 65, 51, 88, 78, 77, 54, 113, 66,
        80, 79, 71, 103, 107, 81, 67, 75, 48, 98, 80, 108, 50, 74, 73, 74, 47, 106, 87, 110, 69,
        87, 50, 103, 43, 119, 120, 83, 103, 113, 104, 90, 65, 78, 105, 65, 65, 84, 80, 52, 118, 88,
        85, 121, 97, 75, 43, 10, 116, 109, 87, 76, 81, 90, 118, 76, 100, 107, 116, 103, 79, 75, 98,
        75, 115, 98, 101, 87, 54, 78, 97, 65, 88, 101, 100, 50, 84, 122, 74, 98, 84, 77, 76, 108,
        122, 120, 81, 108, 70, 79, 103, 72, 75, 115, 104, 104, 71, 83, 114, 54, 116, 106, 121, 80,
        52, 103, 116, 109, 52, 103, 75, 112, 10, 69, 121, 51, 76, 87, 112, 48, 73, 50, 69, 66, 55,
        43, 108, 116, 71, 83, 122, 107, 103, 71, 48, 67, 120, 68, 48, 54, 87, 119, 120, 99, 110,
        97, 103, 54, 85, 107, 97, 52, 52, 69, 79, 110, 77, 113, 48, 52, 52, 55, 51, 76, 74, 65, 49,
        89, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89,
        45, 45, 45, 45, 45, 10,
    ];

    const TEST_DER_KEY: &[u8] = &[
        48, 129, 155, 2, 1, 1, 4, 48, 105, 43, 142, 169, 147, 42, 144, 220, 122, 65, 207, 66, 134,
        215, 14, 216, 165, 68, 190, 12, 13, 215, 52, 206, 170, 4, 243, 134, 130, 68, 2, 43, 70,
        207, 151, 98, 72, 39, 248, 214, 156, 69, 182, 131, 236, 49, 74, 10, 161, 100, 3, 98, 0, 4,
        207, 226, 245, 212, 201, 162, 190, 182, 101, 139, 65, 155, 203, 118, 75, 96, 56, 166, 202,
        177, 183, 150, 232, 214, 128, 93, 231, 118, 79, 50, 91, 76, 194, 229, 207, 20, 37, 20, 232,
        7, 42, 200, 97, 25, 42, 250, 182, 60, 143, 226, 11, 102, 226, 2, 169, 19, 45, 203, 90, 157,
        8, 216, 64, 123, 250, 91, 70, 75, 57, 32, 27, 64, 177, 15, 78, 150, 195, 23, 39, 106, 14,
        148, 145, 174, 56, 16, 233, 204, 171, 78, 56, 239, 114, 201, 3, 86,
    ];

    const SEALED_KEY: &str = "FeVEBYkXSqi/7wNX4KevwA==.2fxA9mj2dCyc+ajM.AQ8y4XsMS6z/r513AOVVQzBVaUNFph//4nCJZVcp8bEi5AvL8iDcWDMMkNKDoJ7e.MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEs8INCcNBaPG5yzuG6V7V9/NJJsXSu7iSUzHw2E4oOvVTokgWStSNThSVtPsvlfh4OBUbKrGdYp0WgKpSRKaIVkYL6fZUswKkiUq7iHiLGdXL2A3/Z+fZhlPUfAruAUVX";

    async fn test_encryption_end_to_end() -> Result<(), TombCryptError> {
        use crate::key_seal::common::{PlainKey, PrivateKey, ProtectedKey};

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
        let imported_public_key =
            EcPublicSignatureKey::import_bytes(&raw_public_key_bytes).await?;
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
        use crate::key_seal::common::{ApiToken, ApiTokenMetadata, Jwt, PrivateKey, PublicKey};
        let key = EcSignatureKey::generate().await?;
        let public_key = key.public_key()?;

        let claims = ApiToken::new("test".to_string(), "test".to_string());
        let token = claims.encode_to(&key).await?;
        let _ = ApiToken::decode_from(&token, &public_key).await?;
        let metadata = ApiTokenMetadata::try_from(token)?;
        let key_id = pretty_fingerprint(&public_key.fingerprint().await?);

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
        use crate::key_seal::common::{ApiToken, Jwt, PrivateKey};
        let key = EcSignatureKey::generate().await?;
        let bad_key = EcSignatureKey::generate().await?;
        let bad_public_key = bad_key.public_key()?;

        let claims = ApiToken::new("test".to_string(), "test".to_string());
        let token = claims.encode_to(&key).await?;
        let _ = ApiToken::decode_from(&token, &bad_public_key).await?;

        Ok(())
    }

    async fn test_pem_key_parse_and_use() -> Result<(), TombCryptError> {
        use crate::key_seal::common::{PrivateKey, ProtectedKey};

        let private_key = EcEncryptionKey::import(TEST_PEM_KEY).await?;
        let protected_key = EncryptedSymmetricKey::import(SEALED_KEY)?;
        let plain_key = protected_key.decrypt_with(&private_key).await?;
        assert_eq!(plain_key.as_ref(), PLAINTEXT_SYMMETRIC_KEY);

        Ok(())
    }

    async fn test_der_key_parse_and_use() -> Result<(), TombCryptError> {
        use crate::key_seal::common::{PrivateKey, ProtectedKey};

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
