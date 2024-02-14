use std::collections::HashMap;
use std::env;
#[cfg(not(target_arch = "wasm32"))]
use std::fs;

#[cfg(not(target_arch = "wasm32"))]
use anyhow::anyhow;
#[cfg(not(target_arch = "wasm32"))]
use anyhow::Result;
#[cfg(not(target_arch = "wasm32"))]
use ini::Ini;
#[cfg(not(target_arch = "wasm32"))]
use log::debug;

use super::constants::*;
#[cfg(not(target_arch = "wasm32"))]
use crate::dirs::expand_homedir;

/// Config for aws services.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Config {
    /// `config_file` will be load from:
    ///
    /// - env value: [`AWS_CONFIG_FILE`]
    /// - default to: `~/.aws/config`
    pub config_file: String,
    /// `shared_credentials_file` will be loaded from:
    ///
    /// - env value: [`AWS_SHARED_CREDENTIALS_FILE`]
    /// - default to: `~/.aws/credentials`
    pub shared_credentials_file: String,
    /// `profile` will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_PROFILE`]
    /// - default to: `default`
    pub profile: String,

    /// `region` will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_REGION`]
    /// - profile config: `region`
    pub region: Option<String>,
    /// `sts_regional_endpoints` will be loaded from:
    ///
    /// - env value: [`AWS_STS_REGIONAL_ENDPOINTS`]
    /// - profile config: `sts_regional_endpoints`
    /// - default to `legacy`
    pub sts_regional_endpoints: String,
    /// `access_key_id` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_ACCESS_KEY_ID`]
    /// - profile config: `aws_access_key_id`
    pub access_key_id: Option<String>,
    /// `secret_access_key` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_SECRET_ACCESS_KEY`]
    /// - profile config: `aws_secret_access_key`
    pub secret_access_key: Option<String>,
    /// `session_token` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_SESSION_TOKEN`]
    /// - profile config: `aws_session_token`
    pub session_token: Option<String>,
    /// `role_arn` value will be load from:
    ///
    /// - this field if it's `is_some`.
    /// - env value: [`AWS_ROLE_ARN`]
    /// - profile config: `role_arn`
    pub role_arn: Option<String>,
    /// `role_session_name` value will be load from:
    ///
    /// - env value: [`AWS_ROLE_SESSION_NAME`]
    /// - profile config: `role_session_name`
    /// - default to `reqsign`.
    pub role_session_name: String,
    /// `external_id` value will be load from:
    ///
    /// - this field if it's `is_some`.
    /// - profile config: `external_id`
    pub external_id: Option<String>,
    /// `web_identity_token_file` value will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AWS_WEB_IDENTITY_TOKEN_FILE`]
    /// - profile config: `web_identity_token_file`
    pub web_identity_token_file: Option<String>,
    /// `ec2_metadata_disabled` value will be loaded from:
    ///
    /// - this field
    /// - env value: [`AWS_EC2_METADATA_DISABLED`]
    pub ec2_metadata_disabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_file: "~/.aws/config".to_string(),
            shared_credentials_file: "~/.aws/credentials".to_string(),
            profile: "default".to_string(),
            region: None,
            sts_regional_endpoints: "legacy".to_string(),
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            role_arn: None,
            role_session_name: "reqsign".to_string(),
            external_id: None,
            web_identity_token_file: None,
            ec2_metadata_disabled: false,
        }
    }
}

impl Config {
    /// Load config from env.
    pub fn from_env(mut self) -> Self {
        let envs = env::vars().collect::<HashMap<_, _>>();

        if let Some(v) = envs.get(AWS_CONFIG_FILE) {
            self.config_file = v.to_string();
        }
        if let Some(v) = envs.get(AWS_SHARED_CREDENTIALS_FILE) {
            self.shared_credentials_file = v.to_string();
        }
        if let Some(v) = envs.get(AWS_PROFILE) {
            self.profile = v.to_string();
        }
        if let Some(v) = envs.get(AWS_REGION) {
            self.region = Some(v.to_string())
        }
        if let Some(v) = envs.get(AWS_STS_REGIONAL_ENDPOINTS) {
            self.sts_regional_endpoints = v.to_string();
        }
        if let Some(v) = envs.get(AWS_ACCESS_KEY_ID) {
            self.access_key_id = Some(v.to_string())
        }
        if let Some(v) = envs.get(AWS_SECRET_ACCESS_KEY) {
            self.secret_access_key = Some(v.to_string())
        }
        if let Some(v) = envs.get(AWS_SESSION_TOKEN) {
            self.session_token = Some(v.to_string())
        }
        if let Some(v) = envs.get(AWS_ROLE_ARN) {
            self.role_arn = Some(v.to_string())
        }
        if let Some(v) = envs.get(AWS_ROLE_SESSION_NAME) {
            self.role_session_name = v.to_string();
        }
        if let Some(v) = envs.get(AWS_WEB_IDENTITY_TOKEN_FILE) {
            self.web_identity_token_file = Some(v.to_string());
        }
        if let Some(v) = envs.get(AWS_EC2_METADATA_DISABLED) {
            self.ec2_metadata_disabled = v == "true";
        }
        self
    }

    /// Load config from profile (and shared profile).
    ///
    /// If the env var AWS_PROFILE is set, this profile will be used,
    /// otherwise the contents of `self.profile` will be used.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_profile(mut self) -> Self {
        // self.profile is checked by the two load methods.
        if let Ok(profile) = env::var(AWS_PROFILE) {
            self.profile = profile;
        }

        // make sure we're getting profile info from the correct place.
        // Respecting these env vars also makes it possible to unit test
        // this method.
        if let Ok(config_file) = env::var(AWS_CONFIG_FILE) {
            self.config_file = config_file;
        }

        if let Ok(shared_credentials_file) = env::var(AWS_SHARED_CREDENTIALS_FILE) {
            self.shared_credentials_file = shared_credentials_file;
        }

        // Ignore all errors happened internally.
        let _ = self.load_via_profile_config_file().map_err(|err| {
            debug!("load_via_profile_config_file failed: {err:?}");
        });

        let _ = self
            .load_via_profile_shared_credentials_file()
            .map_err(|err| debug!("load_via_profile_shared_credentials_file failed: {err:?}"));

        self
    }

    /// Only the following fields will exist in shared_credentials_file:
    ///
    /// - `aws_access_key_id`
    /// - `aws_secret_access_key`
    /// - `aws_session_token`
    #[cfg(not(target_arch = "wasm32"))]
    fn load_via_profile_shared_credentials_file(&mut self) -> Result<()> {
        let path = expand_homedir(&self.shared_credentials_file)
            .ok_or_else(|| anyhow!("expand homedir failed"))?;

        let _ = fs::metadata(&path)?;

        let conf = Ini::load_from_file(path)?;

        let props = conf
            .section(Some(&self.profile))
            .ok_or_else(|| anyhow!("section {} is not found", self.profile))?;

        if let Some(v) = props.get("aws_access_key_id") {
            self.access_key_id = Some(v.to_string())
        }
        if let Some(v) = props.get("aws_secret_access_key") {
            self.secret_access_key = Some(v.to_string())
        }
        if let Some(v) = props.get("aws_session_token") {
            self.session_token = Some(v.to_string())
        }

        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn load_via_profile_config_file(&mut self) -> Result<()> {
        let path =
            expand_homedir(&self.config_file).ok_or_else(|| anyhow!("expand homedir failed"))?;

        let _ = fs::metadata(&path)?;

        let conf = Ini::load_from_file(path)?;

        let section = match self.profile.as_str() {
            "default" => "default".to_string(),
            x => format!("profile {x}"),
        };
        let props = conf
            .section(Some(section))
            .ok_or_else(|| anyhow!("section {} is not found", self.profile))?;

        if let Some(v) = props.get("region") {
            self.region = Some(v.to_string())
        }
        if let Some(v) = props.get("sts_regional_endpoints") {
            self.sts_regional_endpoints = v.to_string();
        }
        if let Some(v) = props.get("aws_access_key_id") {
            self.access_key_id = Some(v.to_string())
        }
        if let Some(v) = props.get("aws_secret_access_key") {
            self.secret_access_key = Some(v.to_string())
        }
        if let Some(v) = props.get("aws_session_token") {
            self.session_token = Some(v.to_string())
        }
        if let Some(v) = props.get("role_arn") {
            self.role_arn = Some(v.to_string())
        }
        if let Some(v) = props.get("role_session_name") {
            self.role_session_name = v.to_string()
        }
        if let Some(v) = props.get("web_identity_token_file") {
            self.web_identity_token_file = Some(v.to_string())
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_config_from_profile_shared_credentials() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        // Create a dummy credentials file to test against
        let tmp_dir = tempdir()?;
        let file_path = tmp_dir.path().join("credentials");
        let mut tmp_file = File::create(&file_path)?;
        writeln!(tmp_file, "[default]")?;
        writeln!(tmp_file, "aws_access_key_id = DEFAULTACCESSKEYID")?;
        writeln!(tmp_file, "aws_secret_access_key = DEFAULTSECRETACCESSKEY")?;
        writeln!(tmp_file, "aws_session_token = DEFAULTSESSIONTOKEN")?;
        writeln!(tmp_file)?;
        writeln!(tmp_file, "[profile1]")?;
        writeln!(tmp_file, "aws_access_key_id = PROFILE1ACCESSKEYID")?;
        writeln!(tmp_file, "aws_secret_access_key = PROFILE1SECRETACCESSKEY")?;
        writeln!(tmp_file, "aws_session_token = PROFILE1SESSIONTOKEN")?;

        temp_env::with_vars(
            [
                (AWS_PROFILE, Some("profile1".to_owned())),
                (AWS_CONFIG_FILE, None::<String>),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(file_path.to_str().unwrap().to_owned()),
                ),
            ],
            || {
                let config = Config::default().from_profile();

                assert_eq!(config.profile, "profile1".to_owned());
                assert_eq!(config.access_key_id, Some("PROFILE1ACCESSKEYID".to_owned()));
                assert_eq!(
                    config.secret_access_key,
                    Some("PROFILE1SECRETACCESSKEY".to_owned())
                );
                assert_eq!(
                    config.session_token,
                    Some("PROFILE1SESSIONTOKEN".to_owned())
                );
            },
        );

        Ok(())
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_config_from_profile_config() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        // Create a dummy credentials file to test against
        let tmp_dir = tempdir()?;
        let file_path = tmp_dir.path().join("config");
        let mut tmp_file = File::create(&file_path)?;
        writeln!(tmp_file, "[default]")?;
        writeln!(tmp_file, "aws_access_key_id = DEFAULTACCESSKEYID")?;
        writeln!(tmp_file, "aws_secret_access_key = DEFAULTSECRETACCESSKEY")?;
        writeln!(tmp_file, "aws_session_token = DEFAULTSESSIONTOKEN")?;
        writeln!(tmp_file)?;
        writeln!(tmp_file, "[profile profile1]")?;
        writeln!(tmp_file, "aws_access_key_id = PROFILE1ACCESSKEYID")?;
        writeln!(tmp_file, "aws_secret_access_key = PROFILE1SECRETACCESSKEY")?;
        writeln!(tmp_file, "aws_session_token = PROFILE1SESSIONTOKEN")?;

        temp_env::with_vars(
            [
                (AWS_PROFILE, Some("profile1".to_owned())),
                (
                    AWS_CONFIG_FILE,
                    Some(file_path.to_str().unwrap().to_owned()),
                ),
                (AWS_SHARED_CREDENTIALS_FILE, None::<String>),
            ],
            || {
                let config = Config::default().from_profile();

                assert_eq!(config.profile, "profile1".to_owned());
                assert_eq!(config.access_key_id, Some("PROFILE1ACCESSKEYID".to_owned()));
                assert_eq!(
                    config.secret_access_key,
                    Some("PROFILE1SECRETACCESSKEY".to_owned())
                );
                assert_eq!(
                    config.session_token,
                    Some("PROFILE1SESSIONTOKEN".to_owned())
                );
            },
        );

        Ok(())
    }
}
