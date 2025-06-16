use crate::constants::*;
use reqsign_core::utils::Redact;
use std::env;
use std::fmt::{Debug, Formatter};

/// Config for Tencent COS services.
#[derive(Clone, Default)]
pub struct Config {
    /// Region for Tencent Cloud services
    pub region: Option<String>,
    /// Secret ID (Access Key ID)
    pub secret_id: Option<String>,
    /// Secret Key (Secret Access Key)
    pub secret_key: Option<String>,
    /// Security token for temporary credentials
    pub security_token: Option<String>,
    /// Role ARN for AssumeRole
    pub role_arn: Option<String>,
    /// Role session name, defaults to "reqsign"
    pub role_session_name: Option<String>,
    /// Provider ID for web identity
    pub provider_id: Option<String>,
    /// Web identity token file path
    pub web_identity_token_file: Option<String>,
}

impl Debug for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("region", &self.region)
            .field("secret_id", &Redact::from(&self.secret_id))
            .field("secret_key", &Redact::from(&self.secret_key))
            .field("security_token", &Redact::from(&self.security_token))
            .field("role_arn", &self.role_arn)
            .field("role_session_name", &self.role_session_name)
            .field("provider_id", &self.provider_id)
            .field("web_identity_token_file", &self.web_identity_token_file)
            .finish()
    }
}

impl Config {
    /// Load config from environment variables.
    pub fn from_env() -> Self {
        Self {
            region: env::var(TENCENTCLOUD_REGION)
                .or_else(|_| env::var(TKE_REGION))
                .ok(),
            secret_id: env::var(TENCENTCLOUD_SECRET_ID)
                .or_else(|_| env::var(TKE_SECRET_ID))
                .ok(),
            secret_key: env::var(TENCENTCLOUD_SECRET_KEY)
                .or_else(|_| env::var(TKE_SECRET_KEY))
                .ok(),
            security_token: env::var(TENCENTCLOUD_TOKEN)
                .or_else(|_| env::var(TENCENTCLOUD_SECURITY_TOKEN))
                .ok(),
            role_arn: env::var(TENCENTCLOUD_ROLE_ARN)
                .or_else(|_| env::var(TKE_ROLE_ARN))
                .ok(),
            role_session_name: env::var(TENCENTCLOUD_ROLE_SESSSION_NAME)
                .or_else(|_| env::var(TKE_ROLE_SESSSION_NAME))
                .ok(),
            provider_id: env::var(TENCENTCLOUD_PROVIDER_ID)
                .or_else(|_| env::var(TKE_PROVIDER_ID))
                .ok(),
            web_identity_token_file: env::var(TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE)
                .or_else(|_| env::var(TKE_IDENTITY_TOKEN_FILE))
                .ok(),
        }
    }
}
