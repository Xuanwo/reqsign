use crate::constants::*;
use ini::Ini;
use reqsign_core::utils::Redact;
use reqsign_core::Context;
use reqsign_core::Result;
use std::fmt::{Debug, Formatter};

/// Config for Oracle Cloud Infrastructure services.
#[derive(Clone, Default)]
pub struct Config {
    /// UserID for Oracle Cloud Infrastructure.
    pub user: Option<String>,
    /// TenancyID for Oracle Cloud Infrastructure.
    pub tenancy: Option<String>,
    /// Region for Oracle Cloud Infrastructure.
    pub region: Option<String>,
    /// Private key file path for Oracle Cloud Infrastructure.
    pub key_file: Option<String>,
    /// Fingerprint for the key_file.
    pub fingerprint: Option<String>,
    /// Config file path to load credentials.
    pub config_file: Option<String>,
    /// Profile name in the config file.
    pub profile: Option<String>,
}

impl Debug for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("user", &self.user)
            .field("tenancy", &self.tenancy)
            .field("region", &self.region)
            .field("key_file", &Redact::from(&self.key_file))
            .field("fingerprint", &self.fingerprint)
            .field("config_file", &self.config_file)
            .field("profile", &self.profile)
            .finish()
    }
}

impl Config {
    /// Load config from environment variables.
    pub fn from_env(ctx: &Context) -> Self {
        Self {
            user: ctx.env_var(ORACLE_USER),
            tenancy: ctx.env_var(ORACLE_TENANCY),
            region: ctx.env_var(ORACLE_REGION),
            key_file: ctx.env_var(ORACLE_KEY_FILE),
            fingerprint: ctx.env_var(ORACLE_FINGERPRINT),
            config_file: ctx.env_var(ORACLE_CONFIG_FILE),
            profile: ctx.env_var(ORACLE_PROFILE),
        }
    }

    /// Load config from Oracle config file.
    pub async fn from_config_file(ctx: &Context, path: &str, profile: &str) -> Result<Self> {
        let content = ctx.file_read_as_string(path).await?;
        let ini = Ini::read_from(&mut content.as_bytes()).map_err(|e| {
            reqsign_core::Error::config_invalid(format!("Failed to parse config file: {}", e))
        })?;
        let section = ini.section(Some(profile)).ok_or_else(|| {
            reqsign_core::Error::config_invalid(format!(
                "Profile {} not found in config file",
                profile
            ))
        })?;

        Ok(Self {
            user: section.get("user").map(|s| s.to_string()),
            tenancy: section.get("tenancy").map(|s| s.to_string()),
            region: section.get("region").map(|s| s.to_string()),
            key_file: section.get("key_file").map(|s| s.to_string()),
            fingerprint: section.get("fingerprint").map(|s| s.to_string()),
            config_file: Some(path.to_string()),
            profile: Some(profile.to_string()),
        })
    }
}
