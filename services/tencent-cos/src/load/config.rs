use crate::{Config, Credential};
use async_trait::async_trait;
use log::debug;
use reqsign_core::{Context, ProvideCredential};

/// Static configuration based loader.
#[derive(Debug)]
pub struct ConfigLoader {
    config: Config,
}

impl ConfigLoader {
    /// Create a new ConfigLoader
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ProvideCredential for ConfigLoader {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        match (&self.config.secret_id, &self.config.secret_key) {
            (Some(secret_id), Some(secret_key)) => {
                debug!("loading credential from config");
                Ok(Some(Credential {
                    secret_id: secret_id.clone(),
                    secret_key: secret_key.clone(),
                    security_token: self.config.security_token.clone(),
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
