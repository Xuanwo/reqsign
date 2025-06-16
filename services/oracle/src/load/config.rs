use crate::{Config, Credential};
use async_trait::async_trait;
use log::debug;
use reqsign_core::{Context, Load};

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
impl Load for ConfigLoader {
    type Key = Credential;

    async fn load(&self, _ctx: &Context) -> anyhow::Result<Option<Self::Key>> {
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
