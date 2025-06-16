use reqsign_core::time::{now, DateTime};
use reqsign_core::utils::Redact;
use reqsign_core::Key;
use std::fmt::{Debug, Formatter};

/// Credential that holds the API private key information.
#[derive(Default, Clone)]
pub struct Credential {
    /// TenantID for Oracle Cloud Infrastructure.
    pub tenancy: String,
    /// UserID for Oracle Cloud Infrastructure.
    pub user: String,
    /// API Private Key file path for credential.
    pub key_file: String,
    /// Fingerprint of the API Key.
    pub fingerprint: String,
    /// Expiration time for this credential.
    pub expires_in: Option<DateTime>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("tenancy", &self.tenancy)
            .field("user", &self.user)
            .field("key_file", &Redact::from(&self.key_file))
            .field("fingerprint", &self.fingerprint)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl Key for Credential {
    fn is_valid(&self) -> bool {
        if self.tenancy.is_empty()
            || self.user.is_empty()
            || self.key_file.is_empty()
            || self.fingerprint.is_empty()
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
