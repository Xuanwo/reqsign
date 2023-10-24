use std::collections::HashMap;
use std::env;

use super::constants::*;

/// Config carries all the configuration for Aliyun services.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Config {
    /// `access_key_id` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`ALIBABA_CLOUD_ACCESS_KEY_ID`]
    pub access_key_id: Option<String>,
    /// `access_key_secret` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`ALIBABA_CLOUD_ACCESS_KEY_SECRET`]
    pub access_key_secret: Option<String>,
    /// `security_token` will be loaded from
    ///
    /// - this field if it's `is_some`
    pub security_token: Option<String>,
    /// `role_arn` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`ALIBABA_CLOUD_ROLE_ARN`]
    pub role_arn: Option<String>,
    /// `role_session_name` will be loaded from
    ///
    /// - default to `resign`
    pub role_session_name: String,
    /// `oidc_provider_arn` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`ALIBABA_CLOUD_OIDC_PROVIDER_ARN`]
    pub oidc_provider_arn: Option<String>,
    /// `oidc_token_file` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`ALIBABA_CLOUD_OIDC_TOKEN_FILE`]
    pub oidc_token_file: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            access_key_id: None,
            access_key_secret: None,
            security_token: None,
            role_arn: None,
            role_session_name: "resign".to_string(),
            oidc_provider_arn: None,
            oidc_token_file: None,
        }
    }
}

impl Config {
    /// Load config from env.
    pub fn from_env(mut self) -> Self {
        let envs = env::vars().collect::<HashMap<_, _>>();

        if let Some(v) = envs.get(ALIBABA_CLOUD_ACCESS_KEY_ID) {
            self.access_key_id.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(ALIBABA_CLOUD_ACCESS_KEY_SECRET) {
            self.access_key_secret.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(ALIBABA_CLOUD_SECURITY_TOKEN) {
            self.security_token.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(ALIBABA_CLOUD_ROLE_ARN) {
            self.role_arn.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(ALIBABA_CLOUD_OIDC_PROVIDER_ARN) {
            self.oidc_provider_arn.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(ALIBABA_CLOUD_OIDC_TOKEN_FILE) {
            self.oidc_token_file.get_or_insert(v.clone());
        }

        self
    }
}
