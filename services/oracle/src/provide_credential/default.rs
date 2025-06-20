use crate::constants::{ORACLE_CONFIG_PATH, ORACLE_DEFAULT_PROFILE};
use crate::{Config, Credential};
use async_trait::async_trait;
use log::debug;
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain};
use std::sync::Arc;

/// Default loader for Oracle Cloud Infrastructure.
///
/// This loader will try to load credentials in the following order:
/// 1. From environment variables
/// 2. From the default Oracle config file (~/.oci/config)
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    chain: ProvideCredentialChain<Credential>,
}

impl DefaultCredentialProvider {
    /// Create a new DefaultCredentialProvider
    pub fn new(config: Config) -> Self {
        let chain = ProvideCredentialChain::new()
            .push(EnvCredentialProvider::new(Arc::new(config.clone())))
            .push(ConfigFileCredentialProvider::new(Arc::new(config)));

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

/// Provider that loads credentials from environment variables
#[derive(Debug)]
struct EnvCredentialProvider {
    config: Arc<Config>,
}

impl EnvCredentialProvider {
    fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ProvideCredential for EnvCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Self::Credential>> {
        // Get environment config
        let env_config = Config::from_env(ctx);
        let config = self.config.as_ref();

        // Use environment values if available, otherwise fall back to config
        let tenancy = env_config.tenancy.or_else(|| config.tenancy.clone());
        let user = env_config.user.or_else(|| config.user.clone());
        let key_file = env_config.key_file.or_else(|| config.key_file.clone());
        let fingerprint = env_config
            .fingerprint
            .or_else(|| config.fingerprint.clone());

        match (&tenancy, &user, &key_file, &fingerprint) {
            (Some(tenancy), Some(user), Some(key_file), Some(fingerprint)) => {
                debug!("loading credential from environment variables");
                Ok(Some(Credential {
                    tenancy: tenancy.clone(),
                    user: user.clone(),
                    key_file: key_file.clone(),
                    fingerprint: fingerprint.clone(),
                    expires_in: Some(
                        reqsign_core::time::now()
                            + chrono::TimeDelta::try_minutes(10).expect("in bounds"),
                    ),
                }))
            }
            _ => Ok(None),
        }
    }
}

/// Provider that loads credentials from config file
#[derive(Debug)]
struct ConfigFileCredentialProvider {
    config: Arc<Config>,
}

impl ConfigFileCredentialProvider {
    fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ProvideCredential for ConfigFileCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Self::Credential>> {
        // Determine config file path
        let config_file = self
            .config
            .config_file
            .as_deref()
            .unwrap_or(ORACLE_CONFIG_PATH);

        // Expand home directory if needed
        let expanded_path = ctx
            .expand_home_dir(config_file)
            .ok_or_else(|| reqsign_core::Error::unexpected("Failed to expand home directory"))?;

        // Try to read the file - if it doesn't exist, return None
        let content = match ctx.file_read_as_string(&expanded_path).await {
            Ok(content) => content,
            Err(_) => {
                debug!("Oracle config file not found at {:?}", expanded_path);
                return Ok(None);
            }
        };

        // Determine profile
        let profile = self
            .config
            .profile
            .as_deref()
            .unwrap_or(ORACLE_DEFAULT_PROFILE);

        // Parse INI content
        let ini = ini::Ini::read_from(&mut content.as_bytes())
            .map_err(|e| reqsign_core::Error::config_invalid(format!("Failed to parse config file: {}", e)))?;
        let section = match ini.section(Some(profile)) {
            Some(section) => section,
            None => {
                debug!("Profile {} not found in config file", profile);
                return Ok(None);
            }
        };

        // Extract values
        match (
            section.get("tenancy"),
            section.get("user"),
            section.get("key_file"),
            section.get("fingerprint"),
        ) {
            (Some(tenancy), Some(user), Some(key_file), Some(fingerprint)) => {
                debug!("loading credential from config file");

                // Expand key file path if it starts with ~
                let expanded_key_file = if key_file.starts_with('~') {
                    ctx.expand_home_dir(key_file)
                        .ok_or_else(|| reqsign_core::Error::unexpected("Failed to expand home directory"))?
                } else {
                    key_file.to_string()
                };

                Ok(Some(Credential {
                    tenancy: tenancy.to_string(),
                    user: user.to_string(),
                    key_file: expanded_key_file,
                    fingerprint: fingerprint.to_string(),
                    expires_in: Some(
                        reqsign_core::time::now()
                            + chrono::TimeDelta::try_minutes(10).expect("in bounds"),
                    ),
                }))
            }
            _ => {
                debug!("incomplete config in file, skipping");
                Ok(None)
            }
        }
    }
}
