use std::fmt;
use thiserror::Error;

/// The error type for reqsign operations
#[derive(Error, Debug)]
#[error("{message}")]
pub struct Error {
    kind: ErrorKind,
    message: String,
    #[source]
    source: Option<anyhow::Error>,
}

/// The kind of error that occurred
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Credentials exist but are invalid/malformed
    CredentialInvalid,

    /// Credentials are expired
    CredentialExpired,

    /// Permission denied when accessing credentials
    CredentialDenied,

    /// Request cannot be signed (missing required fields, etc.)
    RequestInvalid,

    /// Configuration error (missing fields, invalid values)
    ConfigInvalid,

    /// Unexpected errors (network, I/O, service errors, etc.)
    Unexpected,
}

impl Error {
    /// Create a new error with the given kind and message
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }

    /// Add a source error
    pub fn with_source(mut self, source: impl Into<anyhow::Error>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Get the error kind
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Check if this is a credential error
    pub fn is_credential_error(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::CredentialInvalid
                | ErrorKind::CredentialExpired
                | ErrorKind::CredentialDenied
        )
    }
}

// Convenience constructors
impl Error {
    /// Create a credential invalid error
    pub fn credential_invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::CredentialInvalid, message)
    }

    /// Create a credential expired error
    pub fn credential_expired(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::CredentialExpired, message)
    }

    /// Create a credential denied error
    pub fn credential_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::CredentialDenied, message)
    }

    /// Create a request invalid error
    pub fn request_invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::RequestInvalid, message)
    }

    /// Create a config invalid error
    pub fn config_invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ConfigInvalid, message)
    }

    /// Create an unexpected error
    pub fn unexpected(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unexpected, message)
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::CredentialInvalid => write!(f, "invalid credentials"),
            ErrorKind::CredentialExpired => write!(f, "expired credentials"),
            ErrorKind::CredentialDenied => write!(f, "credential access denied"),
            ErrorKind::RequestInvalid => write!(f, "invalid request"),
            ErrorKind::ConfigInvalid => write!(f, "invalid configuration"),
            ErrorKind::Unexpected => write!(f, "unexpected error"),
        }
    }
}

/// Convenience type alias for Results
pub type Result<T> = std::result::Result<T, Error>;

// Common From implementations
impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Self::unexpected(err.to_string()).with_source(err)
    }
}

impl From<std::fmt::Error> for Error {
    fn from(err: std::fmt::Error) -> Self {
        Self::unexpected(err.to_string()).with_source(anyhow::Error::from(err))
    }
}

impl From<http::Error> for Error {
    fn from(err: http::Error) -> Self {
        Self::request_invalid(err.to_string()).with_source(anyhow::Error::from(err))
    }
}

impl From<http::header::InvalidHeaderValue> for Error {
    fn from(err: http::header::InvalidHeaderValue) -> Self {
        Self::request_invalid(err.to_string()).with_source(anyhow::Error::from(err))
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(err: http::uri::InvalidUri) -> Self {
        Self::request_invalid(err.to_string()).with_source(anyhow::Error::from(err))
    }
}

impl From<http::uri::InvalidUriParts> for Error {
    fn from(err: http::uri::InvalidUriParts) -> Self {
        Self::request_invalid(err.to_string()).with_source(anyhow::Error::from(err))
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::unexpected(err.to_string()).with_source(anyhow::Error::from(err))
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::unexpected(err.to_string()).with_source(anyhow::Error::from(err))
    }
}

impl From<http::header::InvalidHeaderName> for Error {
    fn from(err: http::header::InvalidHeaderName) -> Self {
        Self::request_invalid(err.to_string()).with_source(anyhow::Error::from(err))
    }
}

impl From<http::header::ToStrError> for Error {
    fn from(err: http::header::ToStrError) -> Self {
        Self::request_invalid(err.to_string()).with_source(anyhow::Error::from(err))
    }
}
