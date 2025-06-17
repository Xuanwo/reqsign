use std::fmt::{Debug, Formatter};

use reqsign_core::{utils::Redact, SigningCredential};

/// Credential for obs.
#[derive(Clone)]
pub struct Credential {
    /// Access key id for obs
    pub access_key_id: String,
    /// Secret access key for obs
    pub secret_access_key: String,
    /// security_token for obs.
    pub security_token: Option<String>,
}

impl Credential {
    /// Create a new credential.
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        security_token: Option<String>,
    ) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            security_token,
        }
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &Redact::from(&self.access_key_id))
            .field("secret_access_key", &Redact::from(&self.secret_access_key))
            .field(
                "security_token",
                &self.security_token.as_ref().map(Redact::from),
            )
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        true
    }
}
