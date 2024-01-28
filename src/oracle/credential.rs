use std::sync::Arc;
use std::sync::Mutex;

use anyhow::Result;
use log::debug;

use super::config::Config;
use crate::time::now;
use crate::time::DateTime;

/// Credential that holds the API private key.
/// private_key is optional, because some other credential will be added later
#[derive(Default, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Credential {
    /// API Private Key for credential.
    pub private_key: Option<String>,
    /// Fingerprint of the API Key.
    pub fingerprint: Option<String>,
    /// expires in for credential.
    pub expires_in: Option<DateTime>,
}

impl Credential {
    /// is current cred is valid?
    pub fn is_valid(&self) -> bool {
        self.private_key.is_some() && self.fingerprint.is_some()
    }
}

/// Loader will load credential from different methods.
#[cfg_attr(test, derive(Debug))]
pub struct Loader {
    config: Config,

    credential: Arc<Mutex<Option<Credential>>>,
}

impl Loader {
    /// Create a new loader via client and config.
    pub fn new(config: Config) -> Self {
        Self {
            config,

            credential: Arc::default(),
        }
    }

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
            .load_via_static()
            .map_err(|err| debug!("load credential via static failed: {err:?}"))
        {
            return Ok(Some(cred));
        }

        Ok(None)
    }

    fn load_via_static(&self) -> Result<Option<Credential>> {
        if let (Some(pk), Some(fp)) = (&self.config.private_key, &self.config.fingerprint) {
            Ok(Some(Credential {
                private_key: Some(pk.clone()),
                fingerprint: Some(fp.clone()),
                // Set expires_in to 10 minutes to enforce re-read
                // from file.
                expires_in: Some(now() + chrono::Duration::minutes(10)),
            }))
        } else {
            Ok(None)
        }
    }
}
