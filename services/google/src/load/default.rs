use anyhow::Result;
use log::debug;

use reqsign_core::{Context, Load};

use crate::config::Config;
use crate::key::Credential;

use super::{
    ConfigLoader, ExternalAccountLoader, ImpersonatedServiceAccountLoader, ServiceAccountLoader,
    VmMetadataLoader,
};

/// DefaultLoader tries to load credentials from multiple sources in order.
#[derive(Debug, Clone)]
pub struct DefaultLoader {
    config: Config,
}

impl DefaultLoader {
    /// Create a new DefaultLoader.
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl Load for DefaultLoader {
    type Key = Credential;

    async fn load(&self, ctx: &Context) -> Result<Option<Self::Key>> {
        // First try to load raw credentials from config
        let config_loader = ConfigLoader::new(self.config.clone());
        let raw_cred = config_loader.load(ctx).await?;

        if let Some(raw_cred) = raw_cred {
            // Try service account first - exchange for token if scope is provided
            if let Some(sa) = raw_cred.service_account {
                debug!("loaded service account credential");

                // If we have a scope, exchange for token
                if self.config.scope.is_some() {
                    debug!("exchanging service account for token");
                    let loader = ServiceAccountLoader::new(self.config.clone(), sa);
                    if let Some(token) = loader.load(ctx).await? {
                        return Ok(Some(Credential::Token(token)));
                    }
                } else {
                    // Return service account directly (for signed URLs)
                    return Ok(Some(Credential::ServiceAccount(sa)));
                }
            }

            // Try external account
            if let Some(ea) = raw_cred.external_account {
                debug!("loaded external account credential, exchanging for token");
                let loader = ExternalAccountLoader::new(self.config.clone(), ea);
                if let Some(token) = loader.load(ctx).await? {
                    return Ok(Some(Credential::Token(token)));
                }
            }

            // Try impersonated service account
            if let Some(isa) = raw_cred.impersonated_service_account {
                debug!("loaded impersonated service account credential, exchanging for token");
                let loader = ImpersonatedServiceAccountLoader::new(self.config.clone(), isa);
                if let Some(token) = loader.load(ctx).await? {
                    return Ok(Some(Credential::Token(token)));
                }
            }
        }

        // Try VM metadata as last resort
        if !self.config.disable_env {
            debug!("trying VM metadata loader");
            let vm_loader = VmMetadataLoader::new(self.config.clone());
            if let Some(token) = vm_loader.load(ctx).await? {
                return Ok(Some(Credential::Token(token)));
            }
        }

        Ok(None)
    }
}
