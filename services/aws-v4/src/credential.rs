use reqsign_core::time::{now, DateTime};
use reqsign_core::utils::Redact;
use reqsign_core::SigningCredential;
use std::fmt::{Debug, Formatter};

/// Credential that holds the access_key and secret_key.
#[derive(Default, Clone)]
pub struct Credential {
    /// Access key id for aws services.
    pub access_key_id: String,
    /// Secret access key for aws services.
    pub secret_access_key: String,
    /// Session token for aws services.
    pub session_token: Option<String>,
    /// Expiration time for this credential.
    pub expires_in: Option<DateTime>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &Redact::from(&self.access_key_id))
            .field("secret_access_key", &Redact::from(&self.secret_access_key))
            .field("session_token", &Redact::from(&self.session_token))
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        if (self.access_key_id.is_empty() || self.secret_access_key.is_empty())
            && self.session_token.is_none()
        {
            return false;
        }
        // Take 120s as buffer to avoid edge cases.
        if let Some(valid) = self
            .expires_in
            .map(|v| v > now() + chrono::TimeDelta::try_minutes(2).expect("in bounds"))
        {
            return valid;
        }

        true
    }
}
