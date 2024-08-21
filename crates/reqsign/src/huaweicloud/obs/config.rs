use std::collections::HashMap;
use std::env;

use super::super::constants::*;

/// Config carries all the configuration for Huawei Cloud OBS services.
#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug))]
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
