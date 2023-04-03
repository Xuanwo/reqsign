use std::fmt::Debug;
use std::fmt::{self, Display, Formatter};

/// Result that is a wrapper of `Result<T, reqsign::Error>`
pub type Result<T> = std::result::Result<T, Error>;

/// ErrorKind is all kinds of Error of reqsign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// reqsign don't know what happened here, and no actions other than just
    /// returning it back.
    ///
    /// For example, AWS IAM returns an internal service error.
    Unexpected,
    /// reqsign can't find the credential or token.
    NotFound,
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Unexpected => write!(f, "Unexpected"),
            ErrorKind::NotFound => write!(f, "NotFound"),
        }
    }
}

/// Errors that returned by reqsign.
pub struct Error {
    kind: ErrorKind,
    message: String,
    operation: &'static str,
    source: Option<anyhow::Error>,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.kind, self.operation)?;

        if !self.message.is_empty() {
            write!(f, " => {}", self.message)?;
        }

        if let Some(source) = &self.source {
            write!(f, ", source: {source}")?;
        }

        Ok(())
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // If alternate has been specified, we will print like Debug.
        if f.alternate() {
            let mut de = f.debug_struct("Error");
            de.field("kind", &self.kind);
            de.field("message", &self.message);
            de.field("operation", &self.operation);
            de.field("source", &self.source);
            return de.finish();
        }

        write!(f, "{} at {}", self.kind, self.operation)?;
        if !self.message.is_empty() {
            write!(f, " => {}", self.message)?;
        }
        writeln!(f)?;

        if let Some(source) = &self.source {
            writeln!(f)?;
            writeln!(f, "Source: {source:?}")?;
        }

        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|v| v.as_ref())
    }
}

impl Error {
    /// Create a new Error with error kind and message.
    pub fn new(kind: ErrorKind, message: &str) -> Self {
        Self {
            kind,
            message: message.to_string(),

            operation: "",
            source: None,
        }
    }

    /// Update error's operation.
    pub fn with_operation(mut self, operation: impl Into<&'static str>) -> Self {
        self.operation = operation.into();
        self
    }

    /// Set source for error.
    ///
    /// # Notes
    ///
    /// If the source has been set, we will raise a panic here.
    pub fn set_source(mut self, src: impl Into<anyhow::Error>) -> Self {
        debug_assert!(self.source.is_none(), "the source error has been set");

        self.source = Some(src.into());
        self
    }

    /// Return error's kind.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self {
            kind: ErrorKind::Unexpected,
            message: "sending request failed".to_string(),

            operation: "reqwest",
            source: Some(err.into()),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self {
            kind: ErrorKind::Unexpected,
            message: "serializing or deserializing JSON data failed".to_string(),

            operation: "serde_json",
            source: Some(err.into()),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::Unexpected,
            message: "reading fs failed".to_string(),

            operation: "io",
            source: Some(err.into()),
        }
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        Self {
            kind: ErrorKind::Unexpected,
            message: "serializing or deserializing JSON Web Token data failed".to_string(),

            operation: "jsonwebtoken",
            source: Some(err.into()),
        }
    }
}
