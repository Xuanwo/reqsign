use anyhow::Result;
use log::debug;
use reqsign_core::{Context, Load};

use crate::config::Config;
use crate::key::Credential;
use crate::load::ConfigLoader;

/// DefaultLoader will try to load credential from different sources.
#[derive(Debug, Clone)]
pub struct DefaultLoader {
    config: Config,
}

impl DefaultLoader {
    /// Create a new DefaultLoader
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl Load for DefaultLoader {
    type Key = Credential;

    async fn load(&self, ctx: &Context) -> Result<Option<Self::Key>> {
        // Load config from environment
        let config = self.config.clone().from_env(ctx);
        let config_loader = ConfigLoader::new(config);

        // Try to load from config
        if let Ok(Some(cred)) = config_loader.load(ctx).await {
            debug!("huaweicloud obs credential loaded from config");
            return Ok(Some(cred));
        }

        // Return None if no credential found
        debug!("huaweicloud obs credential not found");
        Ok(None)
    }
}
