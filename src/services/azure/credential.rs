use anyhow::{anyhow, Result};
use std::fmt::{Debug, Formatter};
use std::mem;

#[derive(Default)]
pub struct Builder {
    cred: Credential,
}

impl Builder {
    pub fn account_name(&mut self, account_name: &str) -> &mut Self {
        self.cred.account_name = account_name.to_string();
        self
    }
    pub fn account_key(&mut self, account_key: &str) -> &mut Self {
        self.cred.account_key = account_key.to_string();
        self
    }

    pub fn build(&mut self) -> Result<Credential> {
        if self.cred.account_name.is_empty() {
            return Err(anyhow!("account_name should not be empty"));
        }
        if self.cred.account_key.is_empty() {
            return Err(anyhow!("account_key should not be empty"));
        }

        Ok(mem::take(&mut self.cred))
    }
}

#[derive(Default, Clone)]
pub struct Credential {
    account_name: String,
    account_key: String,
}

impl Credential {
    pub fn builder() -> Builder {
        Builder {
            cred: Default::default(),
        }
    }

    pub fn new(account_name: &str, account_key: &str) -> Self {
        Credential {
            account_name: account_name.to_string(),
            account_key: account_key.to_string(),
        }
    }

    pub fn account_name(&self) -> &str {
        &self.account_name
    }

    pub fn set_account_name(&mut self, account_name: &str) -> &mut Self {
        self.account_name = account_name.to_string();
        self
    }

    pub fn account_key(&self) -> &str {
        &self.account_key
    }

    pub fn set_account_key(&mut self, account_key: &str) -> &mut Self {
        self.account_key = account_key.to_string();
        self
    }

    pub fn is_valid(&self) -> bool {
        if self.account_name.is_empty() || self.account_key.is_empty() {
            return false;
        }

        true
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Credential {{ account_name: {}, secret_key: {}}}",
            redact(&self.account_name),
            redact(&self.account_key),
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
