use crate::constants::*;
use reqsign_core::utils::Redact;
use reqsign_core::Context;
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
    pub fn from_env(ctx: &Context) -> Self {
        Self {
            region: ctx
                .env_var(TENCENTCLOUD_REGION)
                .or_else(|| ctx.env_var(TKE_REGION)),
            secret_id: ctx
                .env_var(TENCENTCLOUD_SECRET_ID)
                .or_else(|| ctx.env_var(TKE_SECRET_ID)),
            secret_key: ctx
                .env_var(TENCENTCLOUD_SECRET_KEY)
                .or_else(|| ctx.env_var(TKE_SECRET_KEY)),
            security_token: ctx
                .env_var(TENCENTCLOUD_TOKEN)
                .or_else(|| ctx.env_var(TENCENTCLOUD_SECURITY_TOKEN)),
            role_arn: ctx
                .env_var(TENCENTCLOUD_ROLE_ARN)
                .or_else(|| ctx.env_var(TKE_ROLE_ARN)),
            role_session_name: ctx
                .env_var(TENCENTCLOUD_ROLE_SESSSION_NAME)
                .or_else(|| ctx.env_var(TKE_ROLE_SESSSION_NAME)),
            provider_id: ctx
                .env_var(TENCENTCLOUD_PROVIDER_ID)
                .or_else(|| ctx.env_var(TKE_PROVIDER_ID)),
            web_identity_token_file: ctx
                .env_var(TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE)
                .or_else(|| ctx.env_var(TKE_IDENTITY_TOKEN_FILE)),
        }
    }
}
