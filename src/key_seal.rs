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

pub fn hex_fingerprint(fingerprint_bytes: &[u8]) -> String {
    fingerprint_bytes
        .iter()
        .fold(String::new(), |chain, byte| format!("{chain}{byte:02x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    const PLAINTEXT_SYMMETRIC_KEY: &[u8; 32] = b"demo-key-do-not-reuse-sample-key";

    const TEST_PEM_KEY: &[u8] = &[
        45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45,
        45, 45, 45, 45, 10, 77, 73, 71, 50, 65, 103, 69, 65, 77, 66, 65, 71, 66, 121, 113, 71, 83,
        77, 52, 57, 65, 103, 69, 71, 66, 83, 117, 66, 66, 65, 65, 105, 66, 73, 71, 101, 77, 73, 71,
        98, 65, 103, 69, 66, 66, 68, 68, 80, 48, 106, 53, 117, 69, 112, 122, 43, 102, 67, 100, 120,
        51, 84, 76, 114, 10, 79, 56, 121, 50, 72, 77, 100, 49, 113, 107, 105, 82, 86, 53, 97, 66,
        108, 73, 69, 73, 49, 104, 103, 73, 50, 56, 67, 73, 110, 67, 53, 98, 106, 99, 75, 69, 97,
        118, 115, 103, 79, 106, 53, 111, 97, 82, 79, 104, 90, 65, 78, 105, 65, 65, 84, 79, 66, 51,
        54, 47, 114, 52, 56, 69, 10, 72, 102, 100, 99, 77, 48, 104, 117, 105, 66, 107, 102, 101,
        101, 108, 71, 67, 100, 115, 55, 100, 53, 48, 56, 115, 47, 111, 57, 121, 104, 104, 112, 117,
        117, 51, 70, 84, 104, 102, 53, 79, 54, 71, 114, 84, 98, 87, 73, 72, 54, 99, 110, 99, 71,
        83, 55, 102, 100, 47, 86, 109, 48, 90, 90, 10, 52, 57, 90, 75, 49, 86, 53, 74, 119, 85,
        111, 81, 76, 117, 71, 68, 113, 114, 69, 103, 73, 102, 113, 75, 65, 83, 82, 70, 102, 82, 86,
        81, 114, 52, 76, 70, 116, 115, 121, 80, 100, 51, 47, 51, 77, 57, 83, 90, 82, 43, 80, 97,
        68, 65, 81, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75,
        69, 89, 45, 45, 45, 45, 45, 10,
    ];

    const TEST_DER_KEY: &[u8] = &[
        48, 129, 155, 2, 1, 1, 4, 48, 207, 210, 62, 110, 18, 156, 254, 124, 39, 113, 221, 50, 235,
        59, 204, 182, 28, 199, 117, 170, 72, 145, 87, 150, 129, 148, 129, 8, 214, 24, 8, 219, 192,
        136, 156, 46, 91, 141, 194, 132, 106, 251, 32, 58, 62, 104, 105, 19, 161, 100, 3, 98, 0, 4,
        206, 7, 126, 191, 175, 143, 4, 29, 247, 92, 51, 72, 110, 136, 25, 31, 121, 233, 70, 9, 219,
        59, 119, 157, 60, 179, 250, 61, 202, 24, 105, 186, 237, 197, 78, 23, 249, 59, 161, 171, 77,
        181, 136, 31, 167, 39, 112, 100, 187, 125, 223, 213, 155, 70, 89, 227, 214, 74, 213, 94,
        73, 193, 74, 16, 46, 225, 131, 170, 177, 32, 33, 250, 138, 1, 36, 69, 125, 21, 80, 175,
        130, 197, 182, 204, 143, 119, 127, 247, 51, 212, 153, 71, 227, 218, 12, 4,
    ];

    const SEALED_KEY: &str = "IsOZbU9AuHemDVCvvD9WnQ==.GajZ6uqi6siOA9ck.FVtz65k9YE5ETzSsLXSgEuyM2rsNQMaD8aO97HtdKuNB2ytZSa7yhm8HTNvcSCwr.MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEoHUTBQwf8mOFzlX0cEw/RPdjCiysFYcBj2vpPo1smqVXEb/jXjewWjDlTQAInRF52I/itE1wc9E0wvtUYpoZUjbWOAQkGebVZ6CFl3lLqaw7mAOkK/6I1t1S/Y4xr8mx";

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
        let key_id = hex_fingerprint(public_key.fingerprint().await?.as_slice());

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
