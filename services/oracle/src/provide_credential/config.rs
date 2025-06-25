#![allow(deprecated)]

use crate::{Config, Credential};
use async_trait::async_trait;
use log::debug;
use reqsign_core::{Context, ProvideCredential, Result};
use std::sync::Arc;

/// Static configuration based loader.
#[derive(Debug)]
pub struct ConfigCredentialProvider {
    config: Arc<Config>,
}

impl ConfigCredentialProvider {
    /// Create a new ConfigCredentialProvider
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ProvideCredential for ConfigCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Merge with environment config
        let env_config = Config::from_env(ctx);
        let config = self.config.as_ref();

        // Use environment values if available, otherwise fall back to config
        let tenancy = env_config.tenancy.or_else(|| config.tenancy.clone());
        let user = env_config.user.or_else(|| config.user.clone());
        let key_file = env_config.key_file.or_else(|| config.key_file.clone());
        let fingerprint = env_config
            .fingerprint
            .or_else(|| config.fingerprint.clone());

        match (&tenancy, &user, &key_file, &fingerprint) {
            (Some(tenancy), Some(user), Some(key_file), Some(fingerprint)) => {
                debug!("loading credential from config");
                Ok(Some(Credential {
                    tenancy: tenancy.clone(),
                    user: user.clone(),
                    key_file: key_file.clone(),
                    fingerprint: fingerprint.clone(),
                    // Set expires_in to 10 minutes to enforce re-read
                    expires_in: Some(
                        reqsign_core::time::now()
                            + chrono::TimeDelta::try_minutes(10).expect("in bounds"),
                    ),
                }))
            }
            _ => {
                debug!("incomplete config, skipping");
                Ok(None)
            }
        }
    }
}
