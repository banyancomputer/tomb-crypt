use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
#[non_exhaustive]
pub struct TombCryptError {
    kind: TombCryptErrorKind,
}

impl TombCryptError {
    pub(crate) fn invalid_utf8(err: std::str::Utf8Error) -> Self {
        Self {
            kind: TombCryptErrorKind::InvalidUtf8(err),
        }
    }
    pub(crate) fn invalid_base64(err: base64ct::Error) -> Self {
        Self {
            kind: TombCryptErrorKind::InvalidBase64(err),
        }
    }
    pub(crate) fn private_key_export_failed(err: impl Into<p384::pkcs8::Error>) -> Self {
        Self {
            kind: TombCryptErrorKind::PrivateKeyExportFailed(err.into()),
        }
    }
    pub(crate) fn private_key_import_failed(err: impl Into<p384::pkcs8::Error>) -> Self {
        Self {
            kind: TombCryptErrorKind::PrivateKeyImportFailed(err.into()),
        }
    }
    // TODO: There's an issue where setting the type to either sec1::der::Error or p384::elliptic_curve::Error
    //       causes a compiler error. For now, bad error type is better than no type.
    pub(crate) fn private_key_export_bytes_failed() -> Self {
        Self {
            kind: TombCryptErrorKind::PrivateKeyExportBytesFailed,
        }
    }
    pub(crate) fn private_key_import_bytes_failed() -> Self {
        Self {
            kind: TombCryptErrorKind::PrivateKeyImportBytesFailed,
        }
    }
    pub(crate) fn public_key_export_failed(err: impl Into<p384::pkcs8::spki::Error>) -> Self {
        Self {
            kind: TombCryptErrorKind::PublicKeyExportFailed(err.into()),
        }
    }
    pub(crate) fn public_key_import_failed(err: impl Into<p384::pkcs8::spki::Error>) -> Self {
        Self {
            kind: TombCryptErrorKind::PublicKeyImportFailed(err.into()),
        }
    }

    pub(crate) fn hkdf_expand_failed(err: impl Into<hkdf::InvalidLength>) -> Self {
        Self {
            kind: TombCryptErrorKind::HkdfExpandFailed(err.into()),
        }
    }

    pub(crate) fn encryption_failed(err: impl Into<aes_gcm::Error>) -> Self {
        Self {
            kind: TombCryptErrorKind::EncryptionFailed(err.into()),
        }
    }

    pub(crate) fn decryption_failed(err: impl Into<aes_gcm::Error>) -> Self {
        Self {
            kind: TombCryptErrorKind::DecryptionFailed(err.into()),
        }
    }

    pub(crate) fn jwt_error(err: impl Into<jwt_simple::Error>) -> Self {
        Self {
            kind: TombCryptErrorKind::JwtError(err.into()),
        }
    }

    pub(crate) fn jwt_missing_claims(claim: &str) -> Self {
        Self {
            kind: TombCryptErrorKind::JwtMissingClaims(claim.to_string()),
        }
    }

    pub(crate) fn jwt_missing_header_field(field: &str) -> Self {
        Self {
            kind: TombCryptErrorKind::JwtMissingHeaderField(field.to_string()),
        }
    }
}

impl Display for TombCryptError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use TombCryptErrorKind::*;

        let msg = match &self.kind {
            PrivateKeyExportFailed(_) => "private key export failed",
            PublicKeyExportFailed(_) => "public key export failed",
            JwtError(_) => "jwt error",
            JwtMissingClaims(_) => "missing jwt claims",
            JwtMissingHeaderField(_) => "missing jwt header field",
            InvalidBase64(_) => "invalid base64",
            InvalidUtf8(_) => "invalid utf8",
            _ => "placeholder",
        };

        f.write_str(msg)
    }
}

impl std::error::Error for TombCryptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TombCryptErrorKind::*;

        match &self.kind {
            // BackgroundGenerationFailed(err) => Some(err),
            // BadFormat(err) => Some(err),
            // PrivateKeyImportFailed(err) => Some(err),
            // // PublicKeyImportFailed(err) => Some(err),
            // PrivateKeyExportFailed(err) => Some(err),
            // PublicKeyExportFailed(err) => Some(err),
            // EcError(err) => Some(err),
            // JwtError(err) => err.source(),
            // InvalidBase64(err) => Some(err),
            InvalidUtf8(err) => Some(err),
            _ => None,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
enum TombCryptErrorKind {
    PrivateKeyExportBytesFailed,
    PrivateKeyImportBytesFailed,
    PrivateKeyExportFailed(p384::pkcs8::Error),
    PrivateKeyImportFailed(p384::pkcs8::Error),
    PublicKeyExportFailed(p384::pkcs8::spki::Error),
    PublicKeyImportFailed(p384::pkcs8::spki::Error),

    HkdfExpandFailed(hkdf::InvalidLength),
    EncryptionFailed(aes_gcm::Error),
    DecryptionFailed(aes_gcm::Error),

    JwtError(jwt_simple::Error),
    JwtMissingClaims(String),
    JwtMissingHeaderField(String),

    InvalidUtf8(std::str::Utf8Error),
    InvalidBase64(base64ct::Error),
}
