use std::fmt::{Debug, Formatter};

use super::constants::*;
use reqsign_core::{Context, utils::Redact};

/// Config carries all the configuration for Huawei Cloud OBS services.
#[derive(Clone, Default)]
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
    pub fn from_env(mut self, ctx: &Context) -> Self {
        if let Some(v) = ctx.env_var(HUAWEI_CLOUD_ACCESS_KEY_ID) {
            self.access_key_id.get_or_insert(v);
        }
        if let Some(v) = ctx.env_var(HUAWEI_CLOUD_SECRET_ACCESS_KEY) {
            self.secret_access_key.get_or_insert(v);
        }
        if let Some(v) = ctx.env_var(HUAWEI_CLOUD_SECURITY_TOKEN) {
            self.security_token.get_or_insert(v);
        }

        self
    }
}

impl Debug for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("access_key_id", &self.access_key_id.as_ref().map(Redact::from))
            .field("secret_access_key", &self.secret_access_key.as_ref().map(Redact::from))
            .field("security_token", &self.security_token.as_ref().map(Redact::from))
            .finish()
    }
}
