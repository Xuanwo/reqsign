use anyhow::Result;
use log::debug;

use reqsign_core::{Context, ProvideCredential};

use crate::config::Config;
use crate::credential::{Credential, RawCredential};
use crate::constants::GOOGLE_APPLICATION_CREDENTIALS;

use super::{
    ConfigLoader, ExternalAccountLoader, ImpersonatedServiceAccountLoader, VmMetadataLoader,
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

    async fn load_raw_credential(&self, ctx: &Context) -> Result<Option<RawCredential>> {
        // Try explicit content
        if let Some(content) = &self.config.credential_content {
            if let Ok(cred) = RawCredential::from_base64(content) {
                return Ok(Some(cred));
            }
        }

        // Try explicit path
        if let Some(path) = &self.config.credential_path {
            if let Ok(content) = ctx.file_read(path).await {
                if let Ok(cred) = RawCredential::from_slice(&content) {
                    return Ok(Some(cred));
                }
            }
        }

        // Try environment variable
        if !self.config.disable_env {
            if let Some(path) = ctx.env_var(GOOGLE_APPLICATION_CREDENTIALS) {
                if let Ok(content) = ctx.file_read(&path).await {
                    if let Ok(cred) = RawCredential::from_slice(&content) {
                        return Ok(Some(cred));
                    }
                }
            }
        }

        // Try well-known location
        if !self.config.disable_well_known_location {
            let config_dir = if let Some(v) = ctx.env_var("APPDATA") {
                v
            } else if let Some(v) = ctx.env_var("XDG_CONFIG_HOME") {
                v
            } else if let Some(v) = ctx.env_var("HOME") {
                format!("{v}/.config")
            } else {
                return Ok(None);
            };

            let path = format!("{config_dir}/gcloud/application_default_credentials.json");
            if let Ok(content) = ctx.file_read(&path).await {
                if let Ok(cred) = RawCredential::from_slice(&content) {
                    return Ok(Some(cred));
                }
            }
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl ProvideCredential for DefaultLoader {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // First try to load credentials from config
        let config_loader = ConfigLoader::new(self.config.clone());
        if let Some(cred) = config_loader.provide_credential(ctx).await? {
            // ConfigLoader returns Credential with service account
            debug!("loaded service account credential from config");
            return Ok(Some(cred));
        }

        // Try to load raw credentials for other types
        let raw_cred = self.load_raw_credential(ctx).await?;
        if let Some(raw_cred) = raw_cred {
            // Try external account
            if let Some(ea) = raw_cred.external_account {
                debug!("loaded external account credential, exchanging for token");
                let loader = ExternalAccountLoader::new(self.config.clone(), ea);
                if let Some(cred) = loader.provide_credential(ctx).await? {
                    return Ok(Some(cred));
                }
            }

            // Try impersonated service account
            if let Some(isa) = raw_cred.impersonated_service_account {
                debug!("loaded impersonated service account credential, exchanging for token");
                let loader = ImpersonatedServiceAccountLoader::new(self.config.clone(), isa);
                if let Some(cred) = loader.provide_credential(ctx).await? {
                    return Ok(Some(cred));
                }
            }
        }

        // Try VM metadata as last resort
        if !self.config.disable_env {
            debug!("trying VM metadata loader");
            let vm_loader = VmMetadataLoader::new(self.config.clone());
            if let Some(cred) = vm_loader.provide_credential(ctx).await? {
                return Ok(Some(cred));
            }
        }

        Ok(None)
    }
}
