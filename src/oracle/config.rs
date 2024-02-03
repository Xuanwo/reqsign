use anyhow::Result;
use serde::Deserialize;
use std::fs::read_to_string;
use toml::from_str;

/// Config carries all the configuration for Oracle services.
/// will be loaded from default config file ~/.oci/config
#[derive(Clone, Default, Deserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct Config {
    /// userID for Oracle Cloud Infrastructure.
    pub user: String,
    /// tenancyID for Oracle Cloud Infrastructure.
    pub tenancy: String,
    /// region for Oracle Cloud Infrastructure.
    pub region: String,
    /// private key file for Oracle Cloud Infrastructure.
    pub key_file: Option<String>,
    /// fingerprint for the key_file.
    pub fingerprint: Option<String>,
}

impl Config {
    /// Load config from env.
    pub fn from_config(path: &str) -> Result<Self> {
        let content = read_to_string(path)?;
        let config = from_str(&content)?;

        Ok(config)
    }
}
