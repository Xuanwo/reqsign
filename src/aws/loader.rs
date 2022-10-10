//! Loader is used to load credential or region from env.
//!
//! - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION
//! - The default credentials files located in ~/.aws/config and ~/.aws/credentials (location can vary per platform)
//! - Web Identity Token credentials from the environment or container (including EKS)
//! - ECS Container Credentials (IAM roles for tasks)
//! - EC2 Instance Metadata Service (IAM Roles attached to instance)

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::sleep;
use std::{env, fs};

use anyhow::{anyhow, Result};
use backon::ExponentialBackoff;
use ini::Ini;
use log::warn;
use quick_xml::de;
use serde::Deserialize;

use super::constants;
use crate::credential::Credential;
use crate::credential::DummyLoader;
use crate::dirs::expand_homedir;
use crate::time::parse_rfc3339;

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug))]
struct Config {
    /// `config_file` will be load from:
    ///
    /// - this field if it's `is_some`
    /// - env value: `AWS_CONFIG_FILE`
    /// - default to: `~/.aws/config`
    config_file: Option<String>,
    /// `shared_credentials_file` will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: `AWS_SHARED_CREDENTIALS_FILE`
    /// - default to: `~/.aws/credentials`
    shared_credentials_file: Option<String>,
    /// `profile` will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: `AWS_PROFILE`
    /// - default to: `default`
    profile: Option<String>,

    /// `region` will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: `AWS_REGION`
    /// - profile config: `region`
    region: Option<String>,
    /// `access_key_id` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: `AWS_ACCESS_KEY_ID`
    /// - profile config: `aws_access_key_id`
    access_key_id: Option<String>,
    /// `secret_access_key` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: `AWS_SECRET_ACCESS_KEY`
    /// - profile config: `aws_secret_access_key`
    secret_access_key: Option<String>,
    /// `session_token` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: `AWS_SESSION_TOKEN`
    /// - profile config: `aws_session_token`
    session_token: Option<String>,
    /// `role_arn` value will be load from:
    ///
    /// - this field if it's `is_some`.
    /// - env value: `AWS_ROLE_ARN`
    /// - profile config: `role_arn`
    role_arn: Option<String>,
    /// `role_session_name` value will be load from:
    ///
    /// - this field if it's `is_some`.
    /// - env value: `AWS_ROLE_SESSION_NAME`
    /// - profile config: `role_session_name`
    /// - default to `reqsign`.
    role_session_name: Option<String>,
    /// `external_id` value will be load from:
    ///
    /// - this field if it's `is_some`.
    /// - profile config: `external_id`
    #[allow(unused)]
    external_id: Option<String>,
    /// `web_identity_token_file` value will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: `AWS_WEB_IDENTITY_TOKEN_FILE`
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
    fn load_via_env(&self) {
        if self.read_env.load(Ordering::Relaxed) {
            return;
        }
        self.read_env.store(true, Ordering::Relaxed);

        let envs = env::vars().collect::<HashMap<_, _>>();
        let mut config = { self.config.read().expect("lock must be valid").clone() };

        if let Some(v) = envs.get(constants::AWS_CONFIG_FILE) {
            config.config_file.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(constants::AWS_SHARED_CREDENTIALS_FILE) {
            config.shared_credentials_file.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(constants::AWS_PROFILE) {
            config.profile.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(constants::AWS_REGION) {
            config.region.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(constants::AWS_ACCESS_KEY_ID) {
            config.access_key_id.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(constants::AWS_SECRET_ACCESS_KEY) {
            config.secret_access_key.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(constants::AWS_SESSION_TOKEN) {
            config.session_token.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(constants::AWS_ROLE_ARN) {
            config.role_arn.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(constants::AWS_ROLE_SESSION_NAME) {
            config.role_session_name.get_or_insert(v.clone());
        }
        if let Some(v) = envs.get(constants::AWS_WEB_IDENTITY_TOKEN_FILE) {
            config.web_identity_token_file.get_or_insert(v.clone());
        }

        *self.config.write().expect("lock must be valid") = config;
    }

    fn load_via_profile(&self) {
        if self.read_profile.load(Ordering::Relaxed) {
            return;
        }
        self.read_profile.store(true, Ordering::Relaxed);

        self.load_via_profile_shared_credentials_file();
        self.load_via_profile_config_file();
    }

    /// Only the following fields will exist in shared_credentials_file:
    ///
    /// - `aws_access_key_id`
    /// - `aws_secret_access_key`
    /// - `aws_session_token`
    fn load_via_profile_shared_credentials_file(&self) {
        let path = match expand_homedir(&self.shared_credentials_file()) {
            Some(v) => v,
            None => {
                warn!("load_via_profile_shared_credentials_file failed while expand_homedir");

                return;
            }
        };

        if let Err(err) = fs::metadata(&path) {
            warn!(
                "load_via_profile_shared_credentials_file failed while check path {path}: {err:?}"
            );

            return;
        }

        let conf = match Ini::load_from_file(path) {
            Ok(v) => v,
            Err(err) => {
                warn!("load_via_profile_shared_credentials_file failed while reading ini: {err:?}");

                return;
            }
        };

        let props = match conf.section(Some(&self.profile())) {
            Some(v) => v,
            None => {
                warn!(
                    "load_via_profile_shared_credentials_file failed: section {} is not exist",
                    self.profile()
                );

                return;
            }
        };

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
    }

    fn load_via_profile_config_file(&self) {
        let path = match expand_homedir(&self.config_file()) {
            Some(v) => v,
            None => {
                warn!("load_via_profile_config_file failed while expand_homedir");

                return;
            }
        };

        if let Err(err) = fs::metadata(&path) {
            warn!("load_via_profile_config_file failed while check path {path}: {err:?}");

            return;
        }

        let conf = match Ini::load_from_file(path) {
            Ok(v) => v,
            Err(err) => {
                warn!("load_via_profile_config_file failed while reading ini: {err:?}");

                return;
            }
        };

        let props = match conf.section(Some(&self.profile())) {
            Some(v) => v,
            None => {
                warn!(
                    "load_via_profile_config_file failed: section {} is not exist",
                    self.profile()
                );

                return;
            }
        };

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

    fn region(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .region
            .clone()
    }

    fn access_key_id(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .access_key_id
            .clone()
    }

    fn secret_access_key(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .secret_access_key
            .clone()
    }

    fn session_token(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .session_token
            .clone()
    }

    fn role_arn(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .role_arn
            .clone()
    }

    fn role_session_name(&self) -> String {
        self.config
            .read()
            .expect("lock must be valid")
            .role_session_name
            .clone()
            .unwrap_or_else(|| "reqsign".to_string())
    }

    #[allow(unused)]
    fn external_id(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .external_id
            .clone()
    }

    fn web_identity_token_file(&self) -> Option<String> {
        self.config
            .read()
            .expect("lock must be valid")
            .web_identity_token_file
            .clone()
    }
}

/// CredentialLoader will load credential from different methods.
#[cfg_attr(test, derive(Debug))]
pub struct CredentialLoader {
    credential: Arc<RwLock<Option<Credential>>>,

    disable_env: bool,
    disable_profile: bool,
    #[allow(unused)]
    disable_assume_role: bool,
    disable_assume_role_with_web_identity: bool,

    client: ureq::Agent,
    config_loader: ConfigLoader,
}

impl Default for CredentialLoader {
    fn default() -> Self {
        Self {
            credential: Arc::new(Default::default()),
            disable_env: false,
            disable_profile: false,
            disable_assume_role: false,
            disable_assume_role_with_web_identity: false,
            client: ureq::Agent::new(),
            config_loader: Default::default(),
        }
    }
}

impl CredentialLoader {
    /// Disable load from env.
    pub fn with_disable_env(mut self) -> Self {
        self.disable_env = true;
        self
    }

    /// Disable load from profile.
    pub fn with_disable_profile(mut self) -> Self {
        self.disable_profile = true;
        self
    }

    /// Disable load from assume role with web identity.
    pub fn with_disable_assume_role_with_web_identity(mut self) -> Self {
        self.disable_assume_role_with_web_identity = true;
        self
    }

    /// Set Credential.
    pub fn with_credential(self, cred: Credential) -> Self {
        *self.credential.write().expect("lock poisoned") = Some(cred);
        self
    }

    /// Set config loader.
    pub fn with_config_loader(mut self, cfg: ConfigLoader) -> Self {
        self.config_loader = cfg;
        self
    }

    /// Load credential.
    pub fn load(&self) -> Option<Credential> {
        // Return cached credential if it's valid.
        match self.credential.read().expect("lock poisoned").clone() {
            Some(cred) if cred.is_valid() => return Some(cred),
            _ => (),
        }

        self.load_via_env()
            .or_else(|| self.load_via_profile())
            .or_else(|| self.load_via_assume_role_with_web_identity())
            .map(|cred| {
                let mut lock = self.credential.write().expect("lock poisoned");
                *lock = Some(cred.clone());

                cred
            })
    }

    fn load_via_env(&self) -> Option<Credential> {
        if self.disable_env {
            return None;
        }

        self.config_loader.load_via_env();

        if let (Some(ak), Some(sk)) = (
            self.config_loader.access_key_id(),
            self.config_loader.secret_access_key(),
        ) {
            let mut cred = Credential::new(&ak, &sk);
            cred.set_security_token(self.config_loader.session_token().as_deref());
            Some(cred)
        } else {
            None
        }
    }

    fn load_via_profile(&self) -> Option<Credential> {
        if self.disable_profile {
            return None;
        }

        self.config_loader.load_via_profile();

        if let (Some(ak), Some(sk)) = (
            self.config_loader.access_key_id(),
            self.config_loader.secret_access_key(),
        ) {
            let mut cred = Credential::new(&ak, &sk);
            cred.set_security_token(self.config_loader.session_token().as_deref());
            Some(cred)
        } else {
            None
        }
    }

    #[allow(unused)]
    fn load_via_assume_role(&self) -> Option<Credential> {
        todo!()
    }

    fn load_via_assume_role_with_web_identity(&self) -> Option<Credential> {
        if self.disable_assume_role_with_web_identity {
            return None;
        }

        // Based on our user reports, AWS STS may need 10s to reach consistency
        // Let's retry 4 times: 1s -> 2s -> 4s -> 8s.
        //
        // Reference: <https://github.com/datafuselabs/opendal/issues/288>
        let mut retry = ExponentialBackoff::default()
            .with_max_times(4)
            .with_jitter();

        loop {
            match self.load_via_assume_role_with_web_identity_inner() {
                Ok(v) => return v,
                Err(e) => match retry.next() {
                    Some(dur) => {
                        sleep(dur);
                        continue;
                    }
                    None => {
                        warn!("load credential via assume role with web identity failed: {e}");
                        return None;
                    }
                },
            }
        }
    }

    fn load_via_assume_role_with_web_identity_inner(&self) -> Result<Option<Credential>> {
        let (token_file, role_arn) = match (
            self.config_loader.web_identity_token_file(),
            self.config_loader.role_arn(),
        ) {
            (Some(token_file), Some(role_arn)) => (token_file, role_arn),
            _ => return Ok(None),
        };

        let token = fs::read_to_string(&token_file)?;
        let role_session_name = self.config_loader.role_session_name();

        // Construct request to AWS STS Service.
        let url = format!("https://sts.amazonaws.com/?Action=AssumeRoleWithWebIdentity&RoleArn={role_arn}&WebIdentityToken={token}&Version=2011-06-15&RoleSessionName={role_session_name}");
        let req = self.client.get(&url).set(
            http::header::CONTENT_TYPE.as_str(),
            "application/x-www-form-urlencoded",
        );

        let resp = req.call()?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.into_string()?;
            return Err(anyhow!("request to AWS STS Services failed: {content}"));
        }

        let resp: AssumeRoleWithWebIdentityResponse = de::from_str(&resp.into_string()?)?;
        let resp_cred = resp.result.credentials;

        let cred = Credential::new(&resp_cred.access_key_id, &resp_cred.secret_access_key)
            .with_security_token(&resp_cred.session_token)
            .with_expires_in(parse_rfc3339(&resp_cred.expiration)?);

        cred.check()?;

        Ok(Some(cred))
    }
}

/// RegionLoader will load region from different sources.
#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct RegionLoader {
    region: Arc<RwLock<Option<String>>>,

    disable_env: bool,
    disable_profile: bool,

    config_loader: ConfigLoader,
}

impl RegionLoader {
    /// Disable load from env.
    pub fn with_disable_env(mut self) -> Self {
        self.disable_env = true;
        self
    }

    /// Disable load from profile.
    pub fn with_disable_profile(mut self) -> Self {
        self.disable_profile = true;
        self
    }

    /// Set static region.
    pub fn with_region(self, region: &str) -> Self {
        *self.region.write().expect("lock poisoned") = Some(region.to_string());

        self
    }

    /// Set config loader
    pub fn with_config_loader(mut self, cfg: ConfigLoader) -> Self {
        self.config_loader = cfg;
        self
    }

    /// Load region.
    pub fn load(&self) -> Option<String> {
        // Return cached credential if it's valid.
        if let Some(region) = self.region.read().expect("lock poisoned").clone() {
            return Some(region);
        }

        self.load_via_env()
            .or_else(|| self.load_via_profile())
            .map(|region| {
                let mut lock = self.region.write().expect("lock poisoned");
                *lock = Some(region.clone());

                region
            })
    }

    fn load_via_env(&self) -> Option<String> {
        if self.disable_env {
            return None;
        }

        self.config_loader.load_via_env();

        self.config_loader.region()
    }

    fn load_via_profile(&self) -> Option<String> {
        if self.disable_profile {
            return None;
        }

        self.config_loader.load_via_profile();

        self.config_loader.region()
    }
}

/// Loader trait will try to load region from different sources.
pub trait RegionLoad: Send + Sync {
    /// Load region from sources.
    ///
    /// - If succeed, return `Ok(Some(region))`
    /// - If not found, return `Ok(None)`
    /// - If unexpected errors happened, return `Err(err)`
    fn load_region(&self) -> Result<Option<String>>;
}

/// RegionLoadChain will try to load region via the insert order.
///
/// - If found, return directly.
/// - If not found, keep going and try next one.
/// - If meeting error, return directly.
#[derive(Default)]
pub struct RegionLoadChain {
    loaders: Vec<Box<dyn RegionLoad + 'static>>,
}

impl RegionLoadChain {
    /// Check if this chain is empty.
    pub fn is_empty(&self) -> bool {
        self.loaders.is_empty()
    }

    /// Insert new loaders into chain.
    pub fn push(&mut self, l: impl RegionLoad + 'static) -> &mut Self {
        self.loaders.push(Box::new(l));

        self
    }
}

impl RegionLoad for RegionLoadChain {
    fn load_region(&self) -> Result<Option<String>> {
        for l in self.loaders.iter() {
            if let Some(r) = l.load_region()? {
                return Ok(Some(r));
            }
        }

        Ok(None)
    }
}

impl RegionLoad for DummyLoader {
    fn load_region(&self) -> Result<Option<String>> {
        Ok(None)
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: AssumeRoleWithWebIdentityResult,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResult {
    credentials: AssumeRoleWithWebIdentityCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

#[cfg(test)]
mod tests {
    use log::debug;
    use quick_xml::de;

    use super::constants::*;
    use super::*;

    #[test]
    fn test_credential_env_loader_without_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars_unset(vec![AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY], || {
            let l = CredentialLoader::default()
                .with_disable_profile()
                .with_disable_assume_role_with_web_identity();
            let x = l.load();
            assert!(x.is_none());
        });
    }

    #[test]
    fn test_credential_env_loader_with_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (AWS_ACCESS_KEY_ID, Some("access_key_id")),
                (AWS_SECRET_ACCESS_KEY, Some("secret_access_key")),
            ],
            || {
                let l = CredentialLoader::default()
                    .with_disable_profile()
                    .with_disable_assume_role_with_web_identity();
                let x = l.load();
                debug!("current loader: {l:?}");

                let x = x.expect("must load succeed");
                assert_eq!("access_key_id", x.access_key());
                assert_eq!("secret_access_key", x.secret_key());
            },
        );
    }

    #[test]
    fn test_credential_profile_loader_from_config() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_config",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/not_exist",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                let l = CredentialLoader::default().with_disable_assume_role_with_web_identity();
                let x = l.load().expect("load must success");
                assert_eq!("config_access_key_id", x.access_key());
                assert_eq!("config_secret_access_key", x.secret_key());
            },
        );
    }

    #[test]
    fn test_credential_profile_loader_from_shared() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/not_exist",
                        env::current_dir()
                            .expect("load must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_credential",
                        env::current_dir()
                            .expect("load must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                let l = CredentialLoader::default().with_disable_assume_role_with_web_identity();
                let x = l.load().expect("load must success");
                assert_eq!("shared_access_key_id", x.access_key());
                assert_eq!("shared_secret_access_key", x.secret_key());
            },
        );
    }

    /// AWS_SHARED_CREDENTIALS_FILE should be taken first.
    #[test]
    fn test_credential_profile_loader_from_both() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_config",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_credential",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                let l = CredentialLoader::default().with_disable_assume_role_with_web_identity();
                let x = l.load().expect("load must success");
                assert_eq!("shared_access_key_id", x.access_key());
                assert_eq!("shared_secret_access_key", x.secret_key());
            },
        );
    }

    #[test]
    fn test_region_env_loader_without_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars_unset(vec![AWS_REGION], || {
            let l = RegionLoader::default();
            let x = l.load();
            assert!(x.is_none());
        });
    }

    #[test]
    fn test_region_env_loader_with_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(vec![(AWS_REGION, Some("test"))], || {
            let l = RegionLoader::default();
            let x = l.load().expect("load must success");
            assert_eq!("test", x);
        });
    }

    #[test]
    fn test_region_profile_loader() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![(
                AWS_CONFIG_FILE,
                Some(format!(
                    "{}/testdata/services/aws/default_config",
                    env::current_dir()
                        .expect("current_dir must exist")
                        .to_string_lossy()
                )),
            )],
            || {
                let l = RegionLoader::default();
                let x = l.load().expect("load must success");
                assert_eq!("test", x);
            },
        );
    }

    #[test]
    fn test_parse_assume_role_with_web_identity_response() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let content = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Audience>test_audience</Audience>
    <AssumedRoleUser>
      <AssumedRoleId>role_id:reqsign</AssumedRoleId>
      <Arn>arn:aws:sts::123:assumed-role/reqsign/reqsign</Arn>
    </AssumedRoleUser>
    <Provider>arn:aws:iam::123:oidc-provider/example.com/</Provider>
    <Credentials>
      <AccessKeyId>access_key_id</AccessKeyId>
      <SecretAccessKey>secret_access_key</SecretAccessKey>
      <SessionToken>session_token</SessionToken>
      <Expiration>2022-05-25T11:45:17Z</Expiration>
    </Credentials>
    <SubjectFromWebIdentityToken>subject</SubjectFromWebIdentityToken>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>b1663ad1-23ab-45e9-b465-9af30b202eba</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>"#;

        let resp: AssumeRoleWithWebIdentityResponse =
            de::from_str(content).expect("xml deserialize must success");

        assert_eq!(&resp.result.credentials.access_key_id, "access_key_id");
        assert_eq!(
            &resp.result.credentials.secret_access_key,
            "secret_access_key"
        );
        assert_eq!(&resp.result.credentials.session_token, "session_token");
        assert_eq!(&resp.result.credentials.expiration, "2022-05-25T11:45:17Z");

        Ok(())
    }
}
