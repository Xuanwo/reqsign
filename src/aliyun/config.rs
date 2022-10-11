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
    /// - env value: [`ALIBABA_CLOUD_ACCESS_KEY_ID`]
    access_key_id: Option<String>,
    /// `access_key_secret` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`ALIBABA_CLOUD_ACCESS_KEY_SECRET`]
    access_key_secret: Option<String>,
    /// `security_token` will be loaded from
    ///
    /// - this field if it's `is_some`
    security_token: Option<String>,
    /// `role_arn` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`ALIBABA_CLOUD_ROLE_ARN`]
    role_arn: Option<String>,
    /// `role_session_name` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - default to `resign`
    role_session_name: Option<String>,
    /// `oidc_provider_arn` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`ALIBABA_CLOUD_OIDC_PROVIDER_ARN`]
    oidc_provider_arn: Option<String>,
    /// `oidc_token_file` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`ALIBABA_CLOUD_OIDC_TOKEN_FILE`]
    oidc_token_file: Option<String>,
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

        if let Some(v) = envs.get(ALIBABA_CLOUD_ACCESS_KEY_ID) {
            config.access_key_id.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(ALIBABA_CLOUD_ACCESS_KEY_SECRET) {
            config.access_key_secret.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(ALIBABA_CLOUD_ROLE_ARN) {
            config.role_arn.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(ALIBABA_CLOUD_OIDC_PROVIDER_ARN) {
            config.oidc_provider_arn.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(ALIBABA_CLOUD_OIDC_TOKEN_FILE) {
            config.oidc_token_file.get_or_insert(v.clone());
        }

        *self.config.write().expect("lock must be valid") = config;
    }

    pub fn access_key_id(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .access_key_id
            .clone()
    }

    pub fn access_key_secret(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .access_key_secret
            .clone()
    }

    pub fn security_token(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .security_token
            .clone()
    }

    pub fn role_arn(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .role_arn
            .clone()
    }

    pub fn role_session_name(&self) -> String {
        self.config
            .read()
            .expect("lock must be valid")
            .role_session_name
            .clone()
            .unwrap_or_else(|| "reqsign".to_string())
    }

    pub fn oidc_provider_arn(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .oidc_provider_arn
            .clone()
    }

    pub fn oidc_token_file(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .oidc_token_file
            .clone()
    }
}
