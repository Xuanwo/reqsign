use std::sync::Arc;
use std::sync::Mutex;

use anyhow::Result;
use log::debug;

use super::config::Config;
use super::constants::ORACLE_CONFIG_PATH;
use crate::time::now;
use crate::time::DateTime;

/// Credential that holds the API private key.
/// private_key_path is optional, because some other credential will be added later
#[derive(Default, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Credential {
    /// TenantID for Oracle Cloud Infrastructure.
    pub tenancy: String,
    /// UserID for Oracle Cloud Infrastructure.
    pub user: String,
    /// API Private Key for credential.
    pub key_file: Option<String>,
    /// Fingerprint of the API Key.
    pub fingerprint: Option<String>,
    /// expires in for credential.
    pub expires_in: Option<DateTime>,
}

impl Credential {
    /// is current cred is valid?
    pub fn is_valid(&self) -> bool {
        self.key_file.is_some()
            && self.fingerprint.is_some()
            && self.expires_in.unwrap_or_default() > now()
    }
}

/// Loader will load credential from different methods.
#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct Loader {
    credential: Arc<Mutex<Option<Credential>>>,
}

impl Loader {
    /// Load credential.
    pub async fn load(&self) -> Result<Option<Credential>> {
        // Return cached credential if it's valid.
        match self.credential.lock().expect("lock poisoned").clone() {
            Some(cred) if cred.is_valid() => return Ok(Some(cred)),
            _ => (),
        }

        let cred = if let Some(cred) = self.load_inner().await? {
            cred
        } else {
            return Ok(None);
        };

        let mut lock = self.credential.lock().expect("lock poisoned");
        *lock = Some(cred.clone());

        Ok(Some(cred))
    }

    async fn load_inner(&self) -> Result<Option<Credential>> {
        if let Ok(Some(cred)) = self
            .load_via_config()
            .map_err(|err| debug!("load credential via static failed: {err:?}"))
        {
            return Ok(Some(cred));
        }

        Ok(None)
    }

    fn load_via_config(&self) -> Result<Option<Credential>> {
        let config = Config::from_config(ORACLE_CONFIG_PATH)?;

        Ok(Some(Credential {
            tenancy: config.tenancy,
            user: config.user,
            key_file: config.key_file,
            fingerprint: config.fingerprint,
            // Set expires_in to 10 minutes to enforce re-read
            // from file.
            expires_in: Some(now() + chrono::Duration::minutes(10)),
        }))
    }
}
