use std::collections::HashMap;
use std::env;

use super::constants::*;

/// Config carries all the configuration for Oracle services.
#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug))]
pub struct Config {
    /// `private_key` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`ORACLE_CLOUD_PRIVATE_KEY`]
    pub private_key: Option<String>,
    /// `fingerprint` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`ORACLE_CLOUD_FINGERPRINT`]
    pub fingerprint: Option<String>,
}

impl Config {
    /// Load config from env.
    pub fn from_env(mut self) -> Self {
        let envs = env::vars().collect::<HashMap<_, _>>();

        if let Some(v) = envs.get(ORACLE_CLOUD_PRIVATE_KEY) {
            self.private_key.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(ORACLE_CLOUD_FRINGERPRINT) {
            self.fingerprint.get_or_insert(v.clone());
        }

        self
    }
}
