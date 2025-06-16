use reqsign_core::Key;

/// Credential for obs.
#[derive(Clone, Debug)]
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

impl Key for Credential {
    fn is_valid(&self) -> bool {
        true
    }
}