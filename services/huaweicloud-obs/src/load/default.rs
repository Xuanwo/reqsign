use anyhow::Result;
use log::debug;
use reqsign_core::{Context, Load};

use crate::config::Config;
use crate::key::Credential;
use crate::load::ConfigLoader;

/// DefaultLoader will try to load credential from different sources.
#[derive(Debug, Clone)]
pub struct DefaultLoader {
    config_loader: ConfigLoader,
}

impl DefaultLoader {
    /// Create a new DefaultLoader
    pub fn new(config: Config) -> Self {
        let config = config.from_env();
        Self {
            config_loader: ConfigLoader::new(config),
        }
    }
}

#[async_trait::async_trait]
impl Load for DefaultLoader {
    type Key = Credential;

    async fn load(&self, ctx: &Context) -> Result<Option<Self::Key>> {
        // Try to load from config
        if let Ok(Some(cred)) = self.config_loader.load(ctx).await {
            debug!("huaweicloud obs credential loaded from config");
            return Ok(Some(cred));
        }

        // Return None if no credential found
        debug!("huaweicloud obs credential not found");
        Ok(None)
    }
}
