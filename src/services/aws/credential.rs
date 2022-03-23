use std::fmt::{Debug, Formatter};
use std::mem;
use std::ops::Add;

use anyhow::{anyhow, Result};

use crate::time::{self, DateTime, Duration};

#[derive(Default)]
pub struct Builder {
    cred: Credential,
}

impl Builder {
    pub fn access_key(&mut self, access_key: &str) -> &mut Self {
        self.cred.access_key = access_key.to_string();
        self
    }
    pub fn secret_key(&mut self, secret_key: &str) -> &mut Self {
        self.cred.secret_key = secret_key.to_string();
        self
    }
    pub fn security_token(&mut self, security_token: &str) -> &mut Self {
        self.cred.security_token = Some(security_token.to_string());
        self
    }
    pub fn expires_in(&mut self, expires_in: DateTime) -> &mut Self {
        self.cred.expires_in = Some(expires_in);
        self
    }
    pub fn build(&mut self) -> Result<Credential> {
        if self.cred.access_key.is_empty() {
            return Err(anyhow!("access_key should not be empty"));
        }
        if self.cred.secret_key.is_empty() {
            return Err(anyhow!("secret_key should not be empty"));
        }

        Ok(mem::take(&mut self.cred))
    }
}

#[derive(Default, Clone)]
pub struct Credential {
    access_key: String,
    secret_key: String,
    security_token: Option<String>,
    expires_in: Option<DateTime>,
}

impl Credential {
    pub fn builder() -> Builder {
        Builder {
            cred: Default::default(),
        }
    }
    pub fn new(access_key: &str, secret_key: &str) -> Self {
        Credential {
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            security_token: None,
            expires_in: None,
        }
    }
    pub fn access_key(&self) -> &str {
        &self.access_key
    }
    pub fn set_access_key(&mut self, access_key: &str) -> &mut Self {
        self.access_key = access_key.to_string();
        self
    }

    pub fn secret_key(&self) -> &str {
        &self.secret_key
    }
    pub fn set_secret_key(&mut self, secret_key: &str) -> &mut Self {
        self.secret_key = secret_key.to_string();
        self
    }

    pub fn security_token(&self) -> Option<&str> {
        self.security_token.as_deref()
    }
    pub fn set_security_token(&mut self, token: Option<&str>) -> &mut Self {
        self.security_token = token.map(|v| v.to_string());
        self
    }

    pub fn set_expires_in(&mut self, expires_in: Option<DateTime>) -> &mut Self {
        self.expires_in = expires_in;
        self
    }

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

fn redact(v: &str) -> &str {
    if v.is_empty() {
        "<empty>"
    } else {
        "<redacted>"
    }
}
