use crate::{Config, Credential};
use async_trait::async_trait;
use log::debug;
use reqsign_core::{Context, Load};

/// Default loader for Tencent COS.
///
/// This loader will try to load credentials in the following order:
/// 1. From static configuration
/// 2. From AssumeRoleWithWebIdentity
#[derive(Debug)]
pub struct DefaultLoader {
    config_loader: super::ConfigLoader,
    assume_role_loader: super::AssumeRoleWithWebIdentityLoader,
}

impl DefaultLoader {
    /// Create a new DefaultLoader
    pub fn new(config: Config) -> Self {
        Self {
            config_loader: super::ConfigLoader::new(config.clone()),
            assume_role_loader: super::AssumeRoleWithWebIdentityLoader::new(config),
        }
    }
}

#[async_trait]
impl Load for DefaultLoader {
    type Key = Credential;

    async fn load(&self, ctx: &Context) -> anyhow::Result<Option<Self::Key>> {
        // Try static config first
        if let Ok(Some(cred)) = self
            .config_loader
            .load(ctx)
            .await
            .map_err(|err| debug!("load credential via config failed: {err:?}"))
        {
            return Ok(Some(cred));
        }

        // Try AssumeRoleWithWebIdentity
        if let Ok(Some(cred)) = self.assume_role_loader.load(ctx).await.map_err(|err| {
            debug!("load credential via assume_role_with_web_identity failed: {err:?}")
        }) {
            return Ok(Some(cred));
        }

        Ok(None)
    }
}
