use std::collections::HashMap;
use std::env;

use super::constants::*;

/// Config carries all the configuration for Tencent COS services.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Config {
    /// `region` will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`TENCENTCLOUD_REGION`] or [`TKE_REGION`]
    pub region: Option<String>,
    /// `access_key_id` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`TENCENTCLOUD_SECRET_ID`] or [`TKE_SECRET_ID`]
    pub secret_id: Option<String>,
    /// `secret_access_key` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`TENCENTCLOUD_SECRET_KEY`] or [`TKE_SECRET_KEY`]
    pub secret_key: Option<String>,
    /// `security_token` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`TENCENTCLOUD_TOKEN`] or [`TENCENTCLOUD_SECURITY_TOKEN`]
    pub security_token: Option<String>,
    /// `role_arn` value will be load from:
    ///
    /// - this field if it's `is_some`.
    /// - env value: [`TENCENTCLOUD_ROLE_ARN`] or [`TKE_ROLE_ARN`]
    pub role_arn: Option<String>,
    /// `role_session_name` value will be load from:
    ///
    /// - env value: [`TENCENTCLOUD_ROLE_SESSSION_NAME`] or [`TKE_ROLE_SESSSION_NAME`]
    /// - default to `reqsign`.
    pub role_session_name: String,
    /// `provider_id` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`TENCENTCLOUD_PROVIDER_ID`] or [`TKE_PROVIDER_ID`]
    pub provider_id: Option<String>,
    /// `web_identity_token_file` will be loaded from
    ///
    /// - this field if it's `is_some`
    /// - env value: [`TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE`] or [`TKE_IDENTITY_TOKEN_FILE`]
    pub web_identity_token_file: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            region: None,
            secret_id: None,
            secret_key: None,
            security_token: None,
            role_arn: None,
            role_session_name: "reqsign".to_string(),
            provider_id: None,
            web_identity_token_file: None,
        }
    }
}

impl Config {
    /// Load config from env.
    pub fn from_env(mut self) -> Self {
        let envs = env::vars().collect::<HashMap<_, _>>();

        if let Some(v) = envs
            .get(TENCENTCLOUD_REGION)
            .or_else(|| envs.get(TKE_REGION))
        {
            self.region = Some(v.to_string());
        }

        if let Some(v) = envs
            .get(TENCENTCLOUD_SECRET_ID)
            .or_else(|| envs.get(TKE_SECRET_ID))
        {
            self.secret_id = Some(v.to_string());
        }

        if let Some(v) = envs
            .get(TENCENTCLOUD_SECRET_KEY)
            .or_else(|| envs.get(TKE_SECRET_KEY))
        {
            self.secret_key = Some(v.to_string());
        }

        if let Some(v) = envs
            .get(TENCENTCLOUD_TOKEN)
            .or_else(|| envs.get(TENCENTCLOUD_SECURITY_TOKEN))
        {
            self.security_token = Some(v.to_string());
        }

        if let Some(v) = envs
            .get(TENCENTCLOUD_ROLE_ARN)
            .or_else(|| envs.get(TKE_ROLE_ARN))
        {
            self.role_arn = Some(v.to_string());
        }

        if let Some(v) = envs
            .get(TENCENTCLOUD_ROLE_SESSSION_NAME)
            .or_else(|| envs.get(TKE_ROLE_SESSSION_NAME))
        {
            self.role_session_name = v.to_string();
        }

        if let Some(v) = envs
            .get(TENCENTCLOUD_PROVIDER_ID)
            .or_else(|| envs.get(TKE_PROVIDER_ID))
        {
            self.provider_id = Some(v.to_string());
        }

        if let Some(v) = envs
            .get(TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE)
            .or_else(|| envs.get(TKE_IDENTITY_TOKEN_FILE))
        {
            self.web_identity_token_file = Some(v.to_string());
        }

        self
    }
}
