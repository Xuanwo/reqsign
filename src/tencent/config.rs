use std::collections::HashMap;
use std::env;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;

use super::constants::*;

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug))]
struct Config {
    /// `access_key_id` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`TENCENT_CLOUD_ACCESS_KEY_SECRET`]
    secret_key: Option<String>,
    /// `access_key_secret` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`TENCENT_CLOUD_ACCESS_KEY_ID`]
    secret_id: Option<String>,

    /// `security_token` will be loaded from
    ///
    /// - this field if it's `is_some`
    security_token: Option<String>,
}

/// Config loader that will load config from different source.
#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct ConfigLoader {
    config: Arc<RwLock<Config>>,

    /// Mark whether we have read env or not.
    read_env: AtomicBool,
}

impl Clone for ConfigLoader {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            read_env: AtomicBool::from(self.read_env.load(Ordering::Relaxed)),
        }
    }
}

impl ConfigLoader {
    pub fn load_via_env(&self) {
        if self.read_env.load(Ordering::Relaxed) {
            return;
        }
        self.read_env.store(true, Ordering::Relaxed);

        let envs = env::vars().collect::<HashMap<_, _>>();
        let mut config = { self.config.read().expect("lock must be valid").clone() };

        if let Some(v) = envs.get(TENCENT_CLOUD_ACCESS_KEY_SECRET) {
            config.secret_key.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(TENCENT_CLOUD_ACCESS_KEY_ID) {
            config.secret_id.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(TENCENT_CLOUD_SECRET_TOKEN) {
            config.security_token.get_or_insert(v.clone());
        }

        *self.config.write().expect("lock must be valid") = config;
    }

    pub fn secret_key(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .secret_key
            .clone()
    }

    pub fn secret_id(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .secret_id
            .clone()
    }

        pub(crate) fn security_token(&self) -> Option<String> {
            self.config
                .read()
                .expect("lock must be valid")
                .security_token
                .clone()
        }
}
