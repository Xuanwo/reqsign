use crate::{Config, Credential};
use async_trait::async_trait;
use log::debug;
use reqsign_core::{Context, ProvideCredential};

/// Default loader for Tencent COS.
///
/// This loader will try to load credentials in the following order:
/// 1. From static configuration
/// 2. From AssumeRoleWithWebIdentity
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    config_loader: super::ConfigCredentialProvider,
    assume_role_loader: super::AssumeRoleWithWebIdentityCredentialProvider,
}

impl DefaultCredentialProvider {
    /// Create a new DefaultCredentialProvider
    pub fn new(config: Config) -> Self {
        Self {
            config_loader: super::ConfigCredentialProvider::new(config.clone()),
            assume_role_loader: super::AssumeRoleWithWebIdentityCredentialProvider::new(config),
        }
    }
}

#[async_trait]
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        // Try static config first
        if let Ok(Some(cred)) = self
            .config_loader
            .provide_credential(ctx)
            .await
            .map_err(|err| debug!("load credential via config failed: {err:?}"))
        {
            return Ok(Some(cred));
        }

        // Try AssumeRoleWithWebIdentity
        if let Ok(Some(cred)) = self
            .assume_role_loader
            .provide_credential(ctx)
            .await
            .map_err(|err| {
                debug!("load credential via assume_role_with_web_identity failed: {err:?}")
            })
        {
            return Ok(Some(cred));
        }

        Ok(None)
    }
}
