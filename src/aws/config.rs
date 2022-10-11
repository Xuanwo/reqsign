use std::collections::HashMap;
use std::env;
use std::fs;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;

use anyhow::{anyhow, Result};
use ini::Ini;
use log::warn;

use super::constants::*;
use crate::dirs::expand_homedir;

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug))]
struct Config {
    /// `config_file` will be load from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_CONFIG_FILE`]
    /// - default to: `~/.aws/config`
    config_file: Option<String>,
    /// `shared_credentials_file` will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_SHARED_CREDENTIALS_FILE`]
    /// - default to: `~/.aws/credentials`
    shared_credentials_file: Option<String>,
    /// `profile` will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_PROFILE`]
    /// - default to: `default`
    profile: Option<String>,

    /// `region` will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_REGION`]
    /// - profile config: `region`
    region: Option<String>,
    /// `access_key_id` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_ACCESS_KEY_ID`]
    /// - profile config: `aws_access_key_id`
    access_key_id: Option<String>,
    /// `secret_access_key` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_SECRET_ACCESS_KEY`]
    /// - profile config: `aws_secret_access_key`
    secret_access_key: Option<String>,
    /// `session_token` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_SESSION_TOKEN`]
    /// - profile config: `aws_session_token`
    session_token: Option<String>,
    /// `role_arn` value will be load from:
    ///
    /// - this field if it's `is_some`.
    /// - env value: [`AWS_ROLE_ARN`]
    /// - profile config: `role_arn`
    role_arn: Option<String>,
    /// `role_session_name` value will be load from:
    ///
    /// - this field if it's `is_some`.
    /// - env value: [`AWS_ROLE_SESSION_NAME`]
    /// - profile config: `role_session_name`
    /// - default to `reqsign`.
    role_session_name: Option<String>,
    /// `external_id` value will be load from:
    ///
    /// - this field if it's `is_some`.
    /// - profile config: `external_id`
    external_id: Option<String>,
    /// `web_identity_token_file` value will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_WEB_IDENTITY_TOKEN_FILE`]
    /// - profile config: `web_identity_token_file`
    web_identity_token_file: Option<String>,
}

/// Config loader that will load config from different source.
#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct ConfigLoader {
    config: Arc<RwLock<Config>>,

    /// Mark whether we have read env or not.
    read_env: AtomicBool,
    /// Mark whether we have read profile or not.
    read_profile: AtomicBool,
}

impl Clone for ConfigLoader {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            read_env: AtomicBool::from(self.read_env.load(Ordering::Relaxed)),
            read_profile: AtomicBool::from(self.read_profile.load(Ordering::Relaxed)),
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

        if let Some(v) = envs.get(AWS_CONFIG_FILE) {
            config.config_file.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(AWS_SHARED_CREDENTIALS_FILE) {
            config.shared_credentials_file.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(AWS_PROFILE) {
            config.profile.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(AWS_REGION) {
            config.region.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(AWS_ACCESS_KEY_ID) {
            config.access_key_id.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(AWS_SECRET_ACCESS_KEY) {
            config.secret_access_key.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(AWS_SESSION_TOKEN) {
            config.session_token.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(AWS_ROLE_ARN) {
            config.role_arn.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(AWS_ROLE_SESSION_NAME) {
            config.role_session_name.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(AWS_WEB_IDENTITY_TOKEN_FILE) {
            config.web_identity_token_file.get_or_insert(v.clone());
        }

        *self.config.write().expect("lock must be valid") = config;
    }

    pub fn load_via_profile(&self) {
        if self.read_profile.load(Ordering::Relaxed) {
            return;
        }
        self.read_profile.store(true, Ordering::Relaxed);

        // Ignore all errors happened internally.
        let _ = self
            .load_via_profile_shared_credentials_file()
            .map_err(|err| warn!("load_via_profile_shared_credentials_file failed: {err:?}"));
        let _ = self.load_via_profile_config_file().map_err(|err| {
            warn!("load_via_profile_config_file failed: {err:?}");
        });
    }

    /// Only the following fields will exist in shared_credentials_file:
    ///
    /// - `aws_access_key_id`
    /// - `aws_secret_access_key`
    /// - `aws_session_token`
    fn load_via_profile_shared_credentials_file(&self) -> Result<()> {
        let path = expand_homedir(&self.shared_credentials_file())
            .ok_or_else(|| anyhow!("expand homedir failed"))?;

        let _ = fs::metadata(&path)?;

        let conf = Ini::load_from_file(path)?;

        let props = conf
            .section(Some(&self.profile()))
            .ok_or_else(|| anyhow!("section {} is not found", self.profile()))?;

        let mut config = { self.config.read().expect("lock must be valid").clone() };
        if let Some(v) = props.get("aws_access_key_id") {
            config.access_key_id.get_or_insert(v.to_string());
        }
        if let Some(v) = props.get("aws_secret_access_key") {
            config.secret_access_key.get_or_insert(v.to_string());
        }
        if let Some(v) = props.get("aws_session_token") {
            config.session_token.get_or_insert(v.to_string());
        }

        *self.config.write().expect("lock must be valid") = config;

        Ok(())
    }

    fn load_via_profile_config_file(&self) -> Result<()> {
        let path =
            expand_homedir(&self.config_file()).ok_or_else(|| anyhow!("expand homedir failed"))?;

        let _ = fs::metadata(&path)?;

        let conf = Ini::load_from_file(path)?;

        let props = conf
            .section(Some(&self.profile()))
            .ok_or_else(|| anyhow!("section {} is not found", self.profile()))?;

        let mut config = { self.config.read().expect("lock must be valid").clone() };

        if let Some(v) = props.get("region") {
            config.region.get_or_insert(v.to_string());
        }
        if let Some(v) = props.get("aws_access_key_id") {
            config.access_key_id.get_or_insert(v.to_string());
        }
        if let Some(v) = props.get("aws_secret_access_key") {
            config.secret_access_key.get_or_insert(v.to_string());
        }
        if let Some(v) = props.get("aws_session_token") {
            config.session_token.get_or_insert(v.to_string());
        }
        if let Some(v) = props.get("role_arn") {
            config.role_arn.get_or_insert(v.to_string());
        }
        if let Some(v) = props.get("role_session_name") {
            config.role_session_name.get_or_insert(v.to_string());
        }
        if let Some(v) = props.get("web_identity_token_file") {
            config.web_identity_token_file.get_or_insert(v.to_string());
        }

        *self.config.write().expect("lock must be valid") = config;

        Ok(())
    }

    fn config_file(&self) -> String {
        self.config
            .read()
            .expect("lock must be valid")
            .config_file
            .clone()
            .unwrap_or_else(|| "~/.aws/config".to_string())
    }

    fn shared_credentials_file(&self) -> String {
        self.config
            .read()
            .expect("lock must be valid")
            .shared_credentials_file
            .clone()
            .unwrap_or_else(|| "~/.aws/credentials".to_string())
    }

    fn profile(&self) -> String {
        self.config
            .read()
            .expect("lock must be valid")
            .profile
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }

    pub fn region(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .region
            .clone()
    }

    pub fn access_key_id(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .access_key_id
            .clone()
    }

    pub fn secret_access_key(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .secret_access_key
            .clone()
    }

    pub fn session_token(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .session_token
            .clone()
    }

    pub fn role_arn(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .role_arn
            .clone()
    }

    pub fn set_role_arn(&self, v: &str) {
        self.config
            .write()
            .expect("lock must be valid")
            .role_arn
            .replace(v.to_string());
    }

    pub fn role_session_name(&self) -> String {
        self.config
            .read()
            .expect("lock must be valid")
            .role_session_name
            .clone()
            .unwrap_or_else(|| "reqsign".to_string())
    }

    pub fn set_role_session_name(&self, v: &str) {
        self.config
            .write()
            .expect("lock must be valid")
            .role_session_name
            .replace(v.to_string());
    }

    pub fn external_id(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .external_id
            .clone()
    }

    pub fn set_external_id(&self, v: &str) {
        self.config
            .write()
            .expect("lock must be valid")
            .external_id
            .replace(v.to_string());
    }

    pub fn web_identity_token_file(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .web_identity_token_file
            .clone()
    }
}
