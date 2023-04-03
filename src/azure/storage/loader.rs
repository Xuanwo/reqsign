use std::sync::Arc;
use std::sync::Mutex;

use anyhow::Result;

use super::config::Config;
use super::credential::Credential;

/// Loader will load credential from different methods.
#[cfg_attr(test, derive(Debug))]
pub struct Loader {
    config: Config,

    credential: Arc<Mutex<Option<Credential>>>,
}

impl Loader {
    /// Create a new loader via config.
    pub fn new(config: Config) -> Self {
        Self {
            config,

            credential: Arc::default(),
        }
    }

    /// Load credential.
    pub async fn load(&self) -> Result<Option<Credential>> {
        // Return cached credential if it's valid.
        if let Some(cred) = self.credential.lock().expect("lock poisoned").clone() {
            return Ok(Some(cred));
        }

        let cred = self.load_inner().await?;

        let mut lock = self.credential.lock().expect("lock poisoned");
        *lock = cred.clone();

        Ok(cred)
    }

    async fn load_inner(&self) -> Result<Option<Credential>> {
        if let Some(cred) = self.load_via_config()? {
            return Ok(Some(cred));
        }

        Ok(None)
    }

    fn load_via_config(&self) -> Result<Option<Credential>> {
        if let Some(token) = &self.config.sas_token {
            let cred = Credential::SharedAccessSignature(token.clone());
            return Ok(Some(cred));
        }

        if let (Some(ak), Some(sk)) = (&self.config.account_name, &self.config.account_key) {
            let cred = Credential::SharedKey(ak.clone(), sk.clone());
            return Ok(Some(cred));
        }

        Ok(None)
    }
}
