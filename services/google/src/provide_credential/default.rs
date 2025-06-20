use async_trait::async_trait;
use log::debug;

use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain};

use crate::config::Config;
use crate::constants::GOOGLE_APPLICATION_CREDENTIALS;
use crate::credential::{Credential, CredentialFile};

use super::{
    AuthorizedUserCredentialProvider, ExternalAccountCredentialProvider,
    ImpersonatedServiceAccountCredentialProvider, VmMetadataCredentialProvider,
};

/// DefaultCredentialProvider tries to load credentials from multiple sources in order.
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    chain: ProvideCredentialChain<Credential>,
}

impl DefaultCredentialProvider {
    /// Create a new DefaultCredentialProvider.
    pub fn new(config: Config) -> Self {
        // Build the chain based on the configuration
        let mut chain = ProvideCredentialChain::new();

        // Add credential file providers
        chain = chain.push(CredentialFileProvider::new(config.clone()));

        // Add VM metadata provider if environment is not disabled
        if !config.disable_env {
            chain = chain.push(VmMetadataCredentialProvider::new(config));
        }

        Self { chain }
    }
}

#[async_trait]
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Self::Credential>> {
        self.chain.provide_credential(ctx).await
    }
}

/// CredentialFileProvider loads credentials from files and handles all credential types.
#[derive(Debug, Clone)]
struct CredentialFileProvider {
    config: Config,
}

impl CredentialFileProvider {
    fn new(config: Config) -> Self {
        Self { config }
    }

    async fn load_credential_file(&self, ctx: &Context) -> reqsign_core::Result<Option<CredentialFile>> {
        // Try explicit content
        if let Some(content) = &self.config.credential_content {
            if let Ok(cred) = CredentialFile::from_base64(content) {
                return Ok(Some(cred));
            }
        }

        // Try explicit path
        if let Some(path) = &self.config.credential_path {
            if let Ok(content) = ctx.file_read(path).await {
                if let Ok(cred) = CredentialFile::from_slice(&content) {
                    return Ok(Some(cred));
                }
            }
        }

        // Try environment variable
        if !self.config.disable_env {
            if let Some(path) = ctx.env_var(GOOGLE_APPLICATION_CREDENTIALS) {
                if let Ok(content) = ctx.file_read(&path).await {
                    if let Ok(cred) = CredentialFile::from_slice(&content) {
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
                if let Ok(cred) = CredentialFile::from_slice(&content) {
                    return Ok(Some(cred));
                }
            }
        }

        Ok(None)
    }
}

#[async_trait]
impl ProvideCredential for CredentialFileProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Self::Credential>> {
        // Try to load credential file
        if let Some(cred_file) = self.load_credential_file(ctx).await? {
            match cred_file {
                CredentialFile::ServiceAccount(sa) => {
                    debug!("loaded service account credential");
                    return Ok(Some(Credential::with_service_account(sa)));
                }
                CredentialFile::ExternalAccount(ea) => {
                    debug!("loaded external account credential, exchanging for token");
                    let loader = ExternalAccountCredentialProvider::new(self.config.clone(), ea);
                    if let Some(cred) = loader.provide_credential(ctx).await? {
                        return Ok(Some(cred));
                    }
                }
                CredentialFile::ImpersonatedServiceAccount(isa) => {
                    debug!("loaded impersonated service account credential, exchanging for token");
                    let loader =
                        ImpersonatedServiceAccountCredentialProvider::new(self.config.clone(), isa);
                    if let Some(cred) = loader.provide_credential(ctx).await? {
                        return Ok(Some(cred));
                    }
                }
                CredentialFile::AuthorizedUser(au) => {
                    debug!("loaded authorized user credential, exchanging for token");
                    let loader = AuthorizedUserCredentialProvider::new(self.config.clone(), au);
                    if let Some(cred) = loader.provide_credential(ctx).await? {
                        return Ok(Some(cred));
                    }
                }
            }
        }

        Ok(None)
    }
}
