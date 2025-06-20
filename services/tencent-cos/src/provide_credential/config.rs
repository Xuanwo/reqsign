use crate::{Config, Credential};
use async_trait::async_trait;
use log::debug;
use reqsign_core::{Context, ProvideCredential};
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

    async fn provide_credential(&self, ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        // Merge with environment config
        let env_config = Config::from_env(ctx);
        let config = self.config.as_ref();

        // Use environment values if available, otherwise fall back to config
        let secret_id = env_config.secret_id.or_else(|| config.secret_id.clone());
        let secret_key = env_config.secret_key.or_else(|| config.secret_key.clone());
        let security_token = env_config
            .security_token
            .or_else(|| config.security_token.clone());

        match (&secret_id, &secret_key) {
            (Some(secret_id), Some(secret_key)) => {
                debug!("loading credential from config");
                Ok(Some(Credential {
                    secret_id: secret_id.clone(),
                    secret_key: secret_key.clone(),
                    security_token,
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
