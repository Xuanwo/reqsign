use reqsign_core::time::{now, DateTime};
use reqsign_core::utils::Redact;
use reqsign_core::SigningCredential;
use std::fmt::{Debug, Formatter};

/// Credential for Tencent COS.
#[derive(Default, Clone)]
pub struct Credential {
    /// Secret ID
    pub secret_id: String,
    /// Secret Key
    pub secret_key: String,
    /// Security token for temporary credentials
    pub security_token: Option<String>,
    /// Expiration time for this credential
    pub expires_in: Option<DateTime>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("secret_id", &Redact::from(&self.secret_id))
            .field("secret_key", &Redact::from(&self.secret_key))
            .field("security_token", &Redact::from(&self.security_token))
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        if self.secret_id.is_empty() || self.secret_key.is_empty() {
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
