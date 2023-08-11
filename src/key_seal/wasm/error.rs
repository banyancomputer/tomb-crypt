use base64::DecodeError;
use js_sys::Error as JsError;
use jwt_simple::Error as SimpleJwtError;
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
#[non_exhaustive]
pub struct TombCryptError {
    kind: TombCryptErrorKind,
}

impl TombCryptError {
    pub(crate) fn crypto_unavailable(err: JsError) -> Self {
        Self {
            kind: TombCryptErrorKind::CryptoUnavailable(err),
        }
    }

    pub(crate) fn subtle_crypto_error(err: JsError) -> Self {
        Self {
            kind: TombCryptErrorKind::SubtleCryptoError(err),
        }
    }

    pub(crate) fn public_key_unavailable() -> Self {
        Self {
            kind: TombCryptErrorKind::PublicKeyUnavailable(JsError::new(
                "public key was not imported",
            )),
        }
    }

    pub(crate) fn bad_format(err: JsError) -> Self {
        Self {
            kind: TombCryptErrorKind::BadFormat(err),
        }
    }

    pub(crate) fn bad_base64(err: DecodeError) -> Self {
        Self {
            kind: TombCryptErrorKind::InvalidBase64(err),
        }
    }

    pub(crate) fn export_failed(err: JsError) -> Self {
        Self {
            kind: TombCryptErrorKind::ExportFailed(err),
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
    pub(crate) fn jwt_missing_header_field(field: &str) -> Self {
        Self {
            kind: TombCryptErrorKind::JwtMissingHeaderField(field.to_string()),
        }
    }
}

impl Display for TombCryptError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use TombCryptErrorKind::*;

        match &self.kind {
            CryptoUnavailable(err) => {
                let msg = err.as_string().unwrap();
                write!(f, "SubtleCrypto is not available: {msg}")
            }
            SubtleCryptoError(err) => {
                let msg = err.as_string().unwrap();
                write!(f, "SubtleCrypto error: {msg}")
            }
            PublicKeyUnavailable(err) => {
                let msg = err.as_string().unwrap();
                write!(f, "public key was not imported: {msg}")
            }
            BadFormat(err) => {
                let msg = err.as_string().unwrap();
                write!(f, "imported key was malformed: {msg}")
            }
            ExportFailed(err) => {
                let msg = err.as_string().unwrap();
                write!(f, "failed to export key: {msg}")
            }
            InvalidBase64(err) => {
                let msg = err.to_string();
                write!(f, "invalid base64: {msg}")
            }
            JwtError(err) => {
                let msg = err.to_string();
                write!(f, "jwt error: {msg}")
            }
            InvalidUtf8(err) => {
                let msg = err.to_string();
                write!(f, "invalid utf8: {msg}")
            }
            JwtMissingClaims(claim) => {
                write!(f, "missing jwt claim: {claim}")
            },
            JwtMissingHeaderField(field) => {
                write!(f, "missing jwt header field: {field}")
            }
        }
    }
}

impl From<TombCryptError> for JsError {
    fn from(err: TombCryptError) -> Self {
        use TombCryptErrorKind::*;

        match err.kind {
            CryptoUnavailable(err) => err,
            SubtleCryptoError(err) => err,
            PublicKeyUnavailable(err) => err,
            BadFormat(err) => err,
            ExportFailed(err) => err,
            JwtError(err) => JsError::new(&err.to_string()),
            InvalidBase64(err) => JsError::new(&err.to_string()),
            InvalidUtf8(err) => JsError::new(&err.to_string()),
            JwtMissingClaims(claim) => JsError::new(&format!("missing jwt claim: {claim}")),
            JwtMissingHeaderField(field) => {
                JsError::new(&format!("missing jwt header field: {field}"))
            }
        }
    }
}

impl From<JsError> for TombCryptError {
    fn from(err: JsError) -> Self {
        Self::subtle_crypto_error(err)
    }
}

impl std::error::Error for TombCryptError {}

#[derive(Debug)]
#[non_exhaustive]
enum TombCryptErrorKind {
    CryptoUnavailable(JsError),
    SubtleCryptoError(JsError),
    PublicKeyUnavailable(JsError),
    BadFormat(JsError),
    ExportFailed(JsError),
    JwtError(SimpleJwtError),
    JwtMissingClaims(String),
    JwtMissingHeaderField(String),
    InvalidBase64(DecodeError),
    InvalidUtf8(std::str::Utf8Error),
}
