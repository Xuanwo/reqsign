use crate::{Config, Credential};
use async_trait::async_trait;
use log::debug;
use reqsign_core::{Context, ProvideCredential};

/// Static configuration based loader.
#[derive(Debug)]
pub struct ConfigCredentialProvider {
    config: Config,
}

impl ConfigCredentialProvider {
    /// Create a new ConfigCredentialProvider
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ProvideCredential for ConfigCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        match (
            &self.config.tenancy,
            &self.config.user,
            &self.config.key_file,
            &self.config.fingerprint,
        ) {
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
