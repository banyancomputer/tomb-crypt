use std::fmt::{self, Display, Formatter};

use openssl::error::ErrorStack;

#[derive(Debug)]
#[non_exhaustive]
pub struct KeySealError {
    kind: KeySealErrorKind,
}

impl KeySealError {
    pub(crate) fn bad_format(err: ErrorStack) -> Self {
        Self { kind: KeySealErrorKind::BadFormat(err) }
    }

    pub(crate) fn export_failed(err: ErrorStack) -> Self {
        Self { kind: KeySealErrorKind::ExportFailed(err) }
    }
}

impl Display for KeySealError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use KeySealErrorKind::*;

        let msg = match &self.kind {
            BadFormat(_) => "imported key was malformed",
            ExportFailed(_) => "attempt to export key was rejected by underlying library",
        };

        f.write_str(msg)
    }
}

impl std::error::Error for KeySealError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use KeySealErrorKind::*;

        match &self.kind {
            BadFormat(err) => Some(err),
            ExportFailed(err) => Some(err),
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
enum KeySealErrorKind {
    BadFormat(ErrorStack),
    ExportFailed(ErrorStack),
}
