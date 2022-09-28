//! Provide Credential for most services.

use anyhow::anyhow;
use anyhow::Result;
use std::fmt::{Debug, Formatter};
use std::ops::Add;

use crate::time::{self, DateTime, Duration};

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
    pub fn set_security_token(&mut self, token: Option<&str>) -> &mut Self {
        self.security_token = token.map(|v| v.to_string());
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
        if self.access_key.is_empty() || self.secret_key.is_empty() {
            return false;
        }
        // Take 120s as buffer to avoid edge cases.
        if let Some(valid) = self
            .expires_in
            .map(|v| v > time::now().add(Duration::minutes(2)))
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
pub trait CredentialLoad: Send + Sync {
    /// Load credential from sources.
    ///
    /// - If succeed, return `Ok(Some(cred))`
    /// - If not found, return `Ok(None)`
    /// - If unexpected errors happened, return `Err(err)`
    fn load_credential(&self) -> Result<Option<Credential>>;
}

/// CredentialLoadChain will try to load credential via the insert order.
///
/// - If found, return directly.
/// - If not found, keep going and try next one.
/// - If meeting error, return directly.
#[derive(Default)]
pub struct CredentialLoadChain {
    loaders: Vec<Box<dyn CredentialLoad>>,
}

impl CredentialLoadChain {
    /// Check if this chain is empty.
    pub fn is_empty(&self) -> bool {
        self.loaders.is_empty()
    }

    /// Insert new loaders into chain.
    pub fn push(&mut self, l: impl CredentialLoad + 'static) -> &mut Self {
        self.loaders.push(Box::new(l));

        self
    }
}

impl CredentialLoad for CredentialLoadChain {
    fn load_credential(&self) -> Result<Option<Credential>> {
        for l in self.loaders.iter() {
            if let Some(c) = l.load_credential()? {
                return Ok(Some(c));
            }
        }

        Ok(None)
    }
}

/// DummyLoader always returns `Ok(None)`.
///
/// It's useful when users don't want to load credential/region from env.
pub struct DummyLoader {}

impl CredentialLoad for DummyLoader {
    fn load_credential(&self) -> Result<Option<Credential>> {
        Ok(None)
    }
}

fn redact(v: &str) -> &str {
    if v.is_empty() {
        "<empty>"
    } else {
        "<redacted>"
    }
}
