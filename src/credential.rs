//! Provide Credential for most services.

use std::fmt::Debug;
use std::fmt::Formatter;
use std::ops::Add;

use anyhow::anyhow;
use anyhow::Result;

use crate::time::now;
use crate::time::DateTime;

/// Credential that holds the access_key and secret_key.
#[derive(Default, Clone)]
pub struct Credential {
    access_key: String,
    secret_key: String,
    security_token: Option<String>,
    expires_in: Option<DateTime>,
}

impl Credential {
    /// Create a new Credential.
    pub fn new(access_key: &str, secret_key: &str) -> Self {
        Credential {
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            security_token: None,
            expires_in: None,
        }
    }

    /// Get access_key
    pub fn access_key(&self) -> &str {
        &self.access_key
    }
    /// Set access_key
    pub fn set_access_key(&mut self, access_key: &str) -> &mut Self {
        self.access_key = access_key.to_string();
        self
    }

    /// Get secret_key
    pub fn secret_key(&self) -> &str {
        &self.secret_key
    }
    /// Set secret_key
    pub fn set_secret_key(&mut self, secret_key: &str) -> &mut Self {
        self.secret_key = secret_key.to_string();
        self
    }

    /// Get security_token
    pub fn security_token(&self) -> Option<&str> {
        self.security_token.as_deref()
    }
    /// Set security_token
    pub fn set_security_token(&mut self, token: &str) -> &mut Self {
        self.security_token = Some(token.to_string());
        self
    }
    /// Build a credential with security_token
    pub fn with_security_token(mut self, token: &str) -> Self {
        self.security_token = Some(token.to_string());
        self
    }

    /// Set expires_in
    pub fn set_expires_in(&mut self, expires_in: Option<DateTime>) -> &mut Self {
        self.expires_in = expires_in;
        self
    }
    /// Build a credential with expires_in
    pub fn with_expires_in(mut self, expires_in: DateTime) -> Self {
        self.expires_in = Some(expires_in);
        self
    }

    /// is current cred is valid?
    pub fn is_valid(&self) -> bool {
        if (self.access_key.is_empty() || self.secret_key.is_empty())
            && self.security_token.is_none()
        {
            return false;
        }
        // Take 120s as buffer to avoid edge cases.
        if let Some(valid) = self
            .expires_in
            .map(|v| v > now().add(chrono::Duration::minutes(2)))
        {
            return valid;
        }

        true
    }

    /// Check if current credential is valid.se
    pub fn check(&self) -> Result<()> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(anyhow!("credential is invalid"))
        }
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Credential {{ access_key: {}, secret_key: {}, security_token: {} }}",
            redact(&self.access_key),
            redact(&self.secret_key),
            redact(
                self.security_token
                    .as_ref()
                    .unwrap_or(&"".to_string())
                    .as_str()
            )
        )
    }
}

/// Loader trait will try to load credential from different sources.
pub trait CredentialLoad: 'static + Send + Sync + Debug {
    /// Load credential from sources.
    ///
    /// - If succeed, return `Ok(Some(cred))`
    /// - If not found, return `Ok(None)`
    /// - If unexpected errors happened, return `Err(err)`
    fn load_credential(&self) -> Result<Option<Credential>>;
}

fn redact(v: &str) -> &str {
    if v.is_empty() {
        "<empty>"
    } else {
        "<redacted>"
    }
}
