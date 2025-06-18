use anyhow::Result;
use log::debug;
use reqsign_core::{Context, ProvideCredential};

use crate::config::Config;
use crate::credential::Credential;
use crate::provide_credential::ConfigCredentialProvider;

/// DefaultCredentialProvider will try to load credential from different sources.
#[derive(Debug, Clone)]
pub struct DefaultCredentialProvider {
    config: Config,
}

impl DefaultCredentialProvider {
    /// Create a new DefaultCredentialProvider
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Load config from environment
        let config = self.config.clone().from_env(ctx);
        let config_loader = ConfigCredentialProvider::new(config);

        // Try to load from config
        if let Ok(Some(cred)) = config_loader.provide_credential(ctx).await {
            debug!("huaweicloud obs credential loaded from config");
            return Ok(Some(cred));
        }

        // Return None if no credential found
        debug!("huaweicloud obs credential not found");
        Ok(None)
    }
}
