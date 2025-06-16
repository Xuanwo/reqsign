use reqsign_core::time::{now, DateTime};
use reqsign_core::utils::Redact;
use reqsign_core::SigningCredential;
use std::fmt::{Debug, Formatter};

/// Credential that holds the access_key and secret_key.
#[derive(Default, Clone)]
pub struct Credential {
    /// Access key id for aliyun services.
    pub access_key_id: String,
    /// Access key secret for aliyun services.
    pub access_key_secret: String,
    /// Security token for aliyun services.
    pub security_token: Option<String>,
    /// Expiration time for this credential.
    pub expires_in: Option<DateTime>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &Redact::from(&self.access_key_id))
            .field("access_key_secret", &Redact::from(&self.access_key_secret))
            .field("security_token", &Redact::from(&self.security_token))
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        if (self.access_key_id.is_empty() || self.access_key_secret.is_empty())
            && self.security_token.is_none()
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
