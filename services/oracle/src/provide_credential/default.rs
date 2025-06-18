use crate::constants::{ORACLE_CONFIG_PATH, ORACLE_DEFAULT_PROFILE};
use crate::{Config, Credential};
use async_trait::async_trait;
use log::debug;
use reqsign_core::{Context, ProvideCredential};

/// Default loader for Oracle Cloud Infrastructure.
///
/// This loader will try to load credentials in the following order:
/// 1. From environment variables
/// 2. From the default Oracle config file (~/.oci/config)
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    config: Config,
}

impl DefaultCredentialProvider {
    /// Create a new DefaultCredentialProvider
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        // Try to load from environment variables first
        if let Ok(Some(cred)) = self.load_from_env(ctx).await {
            return Ok(Some(cred));
        }

        // Try to load from config file
        if let Ok(Some(cred)) = self.load_from_config_file(ctx).await {
            return Ok(Some(cred));
        }

        Ok(None)
    }
}

impl DefaultCredentialProvider {
    async fn load_from_env(&self, ctx: &Context) -> anyhow::Result<Option<Credential>> {
        // First check if we have config from environment
        let env_config = Config::from_env(ctx);

        match (
            &env_config.tenancy,
            &env_config.user,
            &env_config.key_file,
            &env_config.fingerprint,
        ) {
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

    async fn load_from_config_file(&self, ctx: &Context) -> anyhow::Result<Option<Credential>> {
        // Determine config file path
        let config_file = self
            .config
            .config_file
            .as_deref()
            .unwrap_or(ORACLE_CONFIG_PATH);

        // Expand home directory if needed
        let expanded_path = ctx
            .expand_home_dir(config_file)
            .ok_or_else(|| anyhow::anyhow!("Failed to expand home directory"))?;

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
        let ini = ini::Ini::read_from(&mut content.as_bytes())?;
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
                        .ok_or_else(|| anyhow::anyhow!("Failed to expand home directory"))?
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
