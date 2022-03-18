use std::fmt::{Debug, Formatter};
use std::mem;
use std::ops::Add;
use std::time::SystemTime;

use anyhow::{anyhow, Result};
use time::Duration;

#[derive(Default)]
pub struct Builder {
    cred: Credential,
}

impl Builder {
    pub fn access_acount(&mut self, access_acount: &str) -> &mut Self {
        self.cred.access_acount = access_acount.to_string();
        self
    }
    pub fn access_key(&mut self, access_key: &str) -> &mut Self {
        self.cred.access_key = access_key.to_string();
        self
    }
    pub fn sas_token(&mut self, sas_token: &str) -> &mut Self {
        self.cred.sas_token = Some(sas_token.to_string());
        self
    }
    pub fn expires_in(&mut self, expires_in: SystemTime) -> &mut Self {
        self.cred.expires_in = Some(expires_in);
        self
    }
    pub fn build(&mut self) -> Result<Credential> {
        if self.cred.access_acount.is_empty() {
            return Err(anyhow!("access_acount should not be empty"));
        }
        if self.cred.access_key.is_empty() {
            return Err(anyhow!("access_key should not be empty"));
        }

        Ok(mem::take(&mut self.cred))
    }
}

#[derive(Default, Clone)]
pub struct Credential {
    access_acount: String,
    access_key: String,
    sas_token: Option<String>,
    expires_in: Option<SystemTime>,
}

impl Credential {
    pub fn builder() -> Builder {
        Builder {
            cred: Default::default(),
        }
    }
    pub fn new(access_acount: &str, access_key: &str) -> Self {
        Credential {
            access_acount: access_acount.to_string(),
            access_key: access_key.to_string(),
            sas_token: None,
            expires_in: None,
        }
    }
    pub fn access_acount(&self) -> &str {
        &self.access_acount
    }
    pub fn set_access_acount(&mut self, access_acount: &str) -> &mut Self {
        self.access_acount = access_acount.to_string();
        self
    }

    pub fn access_key(&self) -> &str {
        &self.access_key
    }
    pub fn set_access_key(&mut self, access_key: &str) -> &mut Self {
        self.access_key = access_key.to_string();
        self
    }

    pub fn sas_token(&self) -> Option<&str> {
        self.sas_token.as_deref()
    }
    pub fn set_sas_token(&mut self, token: Option<&str>) -> &mut Self {
        self.sas_token = token.map(|v| v.to_string());
        self
    }

    pub fn set_expires_in(&mut self, expires_in: Option<SystemTime>) -> &mut Self {
        self.expires_in = expires_in;
        self
    }

    pub fn is_valid(&self) -> bool {
        if self.access_acount.is_empty() || self.access_key.is_empty() {
            return false;
        }
        // Take 120s as buffer to avoid edge cases.
        if let Some(valid) = self
            .expires_in
            .map(|v| v > SystemTime::now().add(Duration::minutes(2)))
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
            redact(&self.access_acount),
            redact(&self.access_key),
            redact(self.sas_token.as_ref().unwrap_or(&"".to_string()).as_str())
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
