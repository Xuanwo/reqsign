use anyhow::{anyhow, Result};
use std::fmt::{Debug, Formatter};
use std::mem;
#[derive(Default)]
pub struct Builder {
    cred: Credential,
}

impl Builder {
    pub fn access_name(&mut self, access_name: &str) -> &mut Self {
        self.cred.access_name = access_name.to_string();
        self
    }
    pub fn shared_key(&mut self, shared_key: &str) -> &mut Self {
        self.cred.shared_key = shared_key.to_string();
        self
    }

    pub fn build(&mut self) -> Result<Credential> {
        if self.cred.access_name.is_empty() {
            return Err(anyhow!("access_name should not be empty"));
        }
        if self.cred.shared_key.is_empty() {
            return Err(anyhow!("shared_key should not be empty"));
        }

        Ok(mem::take(&mut self.cred))
    }
}

#[derive(Default, Clone)]
pub struct Credential {
    access_name: String,
    shared_key: String,
}

impl Credential {
    pub fn builder() -> Builder {
        Builder {
            cred: Default::default(),
        }
    }
    pub fn new(access_name: &str, shared_key: &str) -> Self {
        Credential {
            access_name: access_name.to_string(),
            shared_key: shared_key.to_string(),
        }
    }
    pub fn access_name(&self) -> &str {
        &self.access_name
    }
    pub fn set_access_name(&mut self, access_name: &str) -> &mut Self {
        self.access_name = access_name.to_string();
        self
    }

    pub fn shared_key(&self) -> &str {
        &self.shared_key
    }
    pub fn set_shared_key(&mut self, shared_key: &str) -> &mut Self {
        self.shared_key = shared_key.to_string();
        self
    }

    pub fn is_valid(&self) -> bool {
        if self.access_name.is_empty() || self.shared_key.is_empty() {
            return false;
        }

        true
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Credential {{ access_name: {}, secret_key: {}}}",
            redact(&self.access_name),
            redact(&self.shared_key),
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
