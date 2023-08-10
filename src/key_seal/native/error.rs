use jwt_simple::Error as SimpleJwtError;
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
#[non_exhaustive]
pub struct TombCryptError {
    kind: TombCryptErrorKind,
}

impl TombCryptError {
    pub(crate) fn background_generation_failed(err: tokio::task::JoinError) -> Self {
        Self {
            kind: TombCryptErrorKind::BackgroundGenerationFailed(err),
        }
    }

    pub(crate) fn bad_format(err: openssl::error::ErrorStack) -> Self {
        Self {
            kind: TombCryptErrorKind::BadFormat(err),
        }
    }

    pub(crate) fn bad_base64(err: base64::DecodeError) -> Self {
        Self {
            kind: TombCryptErrorKind::InvalidBase64(err),
        }
    }

    pub(crate) fn export_failed(err: openssl::error::ErrorStack) -> Self {
        Self {
            kind: TombCryptErrorKind::ExportFailed(err),
        }
    }

    pub(crate) fn incompatible_derivation(err: openssl::error::ErrorStack) -> Self {
        Self {
            kind: TombCryptErrorKind::IncompatibleDerivationKey(err),
        }
    }

    pub(crate) fn jwt_error(err: SimpleJwtError) -> Self {
        Self {
            kind: TombCryptErrorKind::JwtError(err),
        }
    }

    pub(crate) fn jwt_missing_claims(claim: &str) -> Self {
        Self {
            kind: TombCryptErrorKind::JwtMissingClaims(claim.to_string()),
        }
    }

    pub(crate) fn invalid_utf8(err: std::str::Utf8Error) -> Self {
        Self {
            kind: TombCryptErrorKind::InvalidUtf8(err),
        }
    }
}

impl Display for TombCryptError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use TombCryptErrorKind::*;

        let msg = match &self.kind {
            BackgroundGenerationFailed(_) => "unable to background key generation",
            BadFormat(_) => "imported key was malformed",
            ExportFailed(_) => "attempt to export key was rejected by underlying library",
            JwtError(_) => "jwt error",
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
            BackgroundGenerationFailed(err) => Some(err),
            BadFormat(err) => Some(err),
            ExportFailed(err) => Some(err),
            JwtError(err) => err.source(),
            InvalidUtf8(err) => Some(err),
            _ => None,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
enum TombCryptErrorKind {
    BackgroundGenerationFailed(tokio::task::JoinError),
    BadFormat(openssl::error::ErrorStack),
    ExportFailed(openssl::error::ErrorStack),
    InvalidBase64(base64::DecodeError),
    IncompatibleDerivationKey(openssl::error::ErrorStack),
    JwtError(SimpleJwtError),
    JwtMissingClaims(String),
    InvalidUtf8(std::str::Utf8Error),
}
