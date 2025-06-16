use std::collections::HashMap;
use std::env;

use super::constants::*;

/// Config carries all the configuration for Huawei Cloud OBS services.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// `access_key_id` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`HUAWEI_CLOUD_ACCESS_KEY_ID`]
    pub access_key_id: Option<String>,
    /// `secret_access_key` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`HUAWEI_CLOUD_SECRET_ACCESS_KEY`]
    pub secret_access_key: Option<String>,
    /// `security_token` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`HUAWEI_CLOUD_SECURITY_TOKEN`]
    pub security_token: Option<String>,
}

impl Config {
    /// Create a new Config
    pub fn new() -> Self {
        Self::default()
    }

    /// Set access_key_id
    pub fn with_access_key_id(mut self, access_key_id: impl Into<String>) -> Self {
        self.access_key_id = Some(access_key_id.into());
        self
    }

    /// Set secret_access_key
    pub fn with_secret_access_key(mut self, secret_access_key: impl Into<String>) -> Self {
        self.secret_access_key = Some(secret_access_key.into());
        self
    }

    /// Set security_token
    pub fn with_security_token(mut self, security_token: impl Into<String>) -> Self {
        self.security_token = Some(security_token.into());
        self
    }

    /// Load config from env.
    pub fn from_env(mut self) -> Self {
        let envs = env::vars().collect::<HashMap<_, _>>();

        if let Some(v) = envs.get(HUAWEI_CLOUD_ACCESS_KEY_ID) {
            self.access_key_id.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(HUAWEI_CLOUD_SECRET_ACCESS_KEY) {
            self.secret_access_key.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(HUAWEI_CLOUD_SECURITY_TOKEN) {
            self.security_token.get_or_insert(v.clone());
        }

        self
    }
}
