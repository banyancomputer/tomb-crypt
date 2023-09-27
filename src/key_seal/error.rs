use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
#[non_exhaustive]
pub struct TombCryptError {
    kind: TombCryptErrorKind,
}

impl TombCryptError {
    // pub(crate) fn background_generation_failed(err: tokio::task::JoinError) -> Self {
    //     Self {
    //         kind: TombCryptErrorKind::BackgroundGenerationFailed(err),
    //     }
    // }
    //
    // pub(crate) fn bad_format(err: EllipticCurveError) -> Self {
    //     Self {
    //         kind: TombCryptErrorKind::BadFormat(err),
    //     }
    // }
    //
    // pub(crate) fn bad_base64(err: base64::DecodeError) -> Self {
    //     Self {
    //         kind: TombCryptErrorKind::InvalidBase64(err),
    //     }
    // }

    //
    // pub(crate) fn public_key_export_failed(err: impl Into<pkcs8::Error>) -> Self {
    //     Self {
    //         kind: TombCryptErrorKind::PublicKeyExportFailed(err.into())
    //     }
    // }

    // pub(crate) fn incompatible_derivation(err: EllipticCurveError) -> Self {
    //     Self {
    //         kind: TombCryptErrorKind::IncompatibleDerivationKey(err),
    //     }
    // }
    //
    // pub(crate) fn jwt_error(err: SimpleJwtError) -> Self {
    //     Self {
    //         kind: TombCryptErrorKind::JwtError(err),
    //     }
    // }
    //
    // pub(crate) fn jwt_missing_claims(claim: &str) -> Self {
    //     Self {
    //         kind: TombCryptErrorKind::JwtMissingClaims(claim.to_string()),
    //     }
    // }
    //
    // pub(crate) fn jwt_missing_header_field(field: &str) -> Self {
    //     Self {
    //         kind: TombCryptErrorKind::JwtMissingHeaderField(field.to_string()),
    //     }
    // }
    //
    pub(crate) fn invalid_utf8(err: std::str::Utf8Error) -> Self {
        Self {
            kind: TombCryptErrorKind::InvalidUtf8(err),
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

    pub(crate) fn secret_sharing_failed() -> Self {
        Self {
            kind: TombCryptErrorKind::SecretSharingFailed,
        }
    }
}

impl Display for TombCryptError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use TombCryptErrorKind::*;

        let msg = match &self.kind {
            // BackgroundGenerationFailed(_) => "unable to background key generation",
            // BadFormat(_) => "imported key was malformed",
            // ExportFailed(_) => "attempt to export key was rejecxted by underlying library",
            // PrivateKeyExportFailed(_) => "private key export failed",
            // PublicKeyExportFailed(_) => "public key export failed",
            // EcError(_) => "elliptic curve error",
            // JwtError(_) => "jwt error",
            // JwtMissingClaims(_) => "missing jwt claims",
            // JwtMissingHeaderField(_) => "missing jwt header field",
            // InvalidBase64(_) => "invalid base64",
            // InvalidUtf8(_) => "invalid utf8",
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
    PrivateKeyExportFailed(p384::pkcs8::Error),
    PrivateKeyImportFailed(p384::pkcs8::Error),
    PublicKeyExportFailed(p384::pkcs8::spki::Error),
    PublicKeyImportFailed(p384::pkcs8::spki::Error),

    // TODO: Better error handling
    SecretSharingFailed,

    InvalidUtf8(std::str::Utf8Error),
}
