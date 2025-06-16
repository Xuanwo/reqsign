use reqsign_core::time::{now, DateTime};
use reqsign_core::utils::Redact;
use reqsign_core::Key;
use std::fmt::{Debug, Formatter};

/// Credential that holds the access_key and secret_key.
#[derive(Default, Clone)]
pub struct Credential {
    /// Azure storage account name.
    pub account_name: String,
    /// Azure storage account key.
    pub account_key: String,
    /// SAS (Shared Access Signature) token.
    pub sas_token: Option<String>,
    /// Bearer token for OAuth authentication.
    pub bearer_token: Option<String>,
    /// Expiration time for this credential.
    pub expires_in: Option<DateTime>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("account_name", &Redact::from(&self.account_name))
            .field("account_key", &Redact::from(&self.account_key))
            .field("sas_token", &Redact::from(&self.sas_token))
            .field("bearer_token", &Redact::from(&self.bearer_token))
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl Key for Credential {
    fn is_valid(&self) -> bool {
        // Check if we have any valid credential type
        let has_shared_key = !self.account_name.is_empty() && !self.account_key.is_empty();
        let has_sas_token = self.sas_token.as_ref().is_some_and(|t| !t.is_empty());
        let has_bearer_token = self.bearer_token.as_ref().is_some_and(|t| !t.is_empty());

        if !has_shared_key && !has_sas_token && !has_bearer_token {
            return false;
        }

        // Check expiration for bearer tokens (take 20s as buffer to avoid edge cases)
        if has_bearer_token {
            if let Some(valid) = self
                .expires_in
                .map(|v| v > now() + chrono::TimeDelta::try_seconds(20).expect("in bounds"))
            {
                return valid;
            }
        }

        true
    }
}

impl Credential {
    /// Create a new credential with shared key authentication.
    pub fn with_shared_key(
        account_name: impl Into<String>,
        account_key: impl Into<String>,
    ) -> Self {
        Self {
            account_name: account_name.into(),
            account_key: account_key.into(),
            sas_token: None,
            bearer_token: None,
            expires_in: None,
        }
    }

    /// Create a new credential with SAS token authentication.
    pub fn with_sas_token(sas_token: impl Into<String>) -> Self {
        Self {
            account_name: String::new(),
            account_key: String::new(),
            sas_token: Some(sas_token.into()),
            bearer_token: None,
            expires_in: None,
        }
    }

    /// Create a new credential with bearer token authentication.
    pub fn with_bearer_token(
        bearer_token: impl Into<String>,
        expires_in: Option<DateTime>,
    ) -> Self {
        Self {
            account_name: String::new(),
            account_key: String::new(),
            sas_token: None,
            bearer_token: Some(bearer_token.into()),
            expires_in,
        }
    }
}
