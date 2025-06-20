use crate::{Config, Credential};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use log::debug;
use reqsign_core::time::{now, parse_rfc3339};
use reqsign_core::{Context, ProvideCredential};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Loader that loads credential via AssumeRoleWithWebIdentity.
#[derive(Debug)]
pub struct AssumeRoleWithWebIdentityCredentialProvider {
    config: Arc<Config>,
}

impl AssumeRoleWithWebIdentityCredentialProvider {
    /// Create a new AssumeRoleWithWebIdentityCredentialProvider
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ProvideCredential for AssumeRoleWithWebIdentityCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let (region, token_file, role_arn, provider_id) = match (
            &self.config.region,
            &self.config.web_identity_token_file,
            &self.config.role_arn,
            &self.config.provider_id,
        ) {
            (Some(region), Some(token_file), Some(role_arn), Some(provider_id)) => {
                (region, token_file, role_arn, provider_id)
            }
            _ => {
                let missing = [
                    ("region", self.config.region.is_none()),
                    (
                        "web_identity_token_file",
                        self.config.web_identity_token_file.is_none(),
                    ),
                    ("role_arn", self.config.role_arn.is_none()),
                    ("provider_id", self.config.provider_id.is_none()),
                ]
                .iter()
                .filter_map(|&(k, v)| if v { Some(k) } else { None })
                .collect::<Vec<_>>()
                .join(", ");

                debug!(
                    "assume_role_with_web_identity is not configured fully: [{}] is missing",
                    missing
                );

                return Ok(None);
            }
        };

        let token = ctx.file_read_as_string(token_file).await?;
        let role_session_name = self
            .config
            .role_session_name
            .clone()
            .unwrap_or_else(|| "reqsign".to_string());

        // Construct request to Tencent Cloud STS Service.
        let url = "https://sts.tencentcloudapi.com";
        let bs = serde_json::to_vec(&AssumeRoleWithWebIdentityRequest {
            role_session_name,
            web_identity_token: token,
            role_arn: role_arn.clone(),
            provider_id: provider_id.clone(),
        })?;

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(url)
            .header(AUTHORIZATION.as_str(), "SKIP")
            .header(CONTENT_TYPE.as_str(), "application/json")
            .header(CONTENT_LENGTH, bs.len())
            .header("X-TC-Action", "AssumeRoleWithWebIdentity")
            .header("X-TC-Region", region)
            .header("X-TC-Timestamp", now().timestamp())
            .header("X-TC-Version", "2018-08-13")
            .body(bs.into())?;

        let resp = ctx.http_send(req).await?;
        let status = resp.status();
        let body = resp.into_body();

        if status != http::StatusCode::OK {
            return Err(anyhow!(
                "request to Tencent Cloud STS Services failed: {}",
                String::from_utf8_lossy(&body)
            ));
        }

        let resp: AssumeRoleWithWebIdentityResult = serde_json::from_slice(&body)?;
        if let Some(error) = resp.response.error {
            return Err(anyhow!(
                "request to Tencent Cloud STS Services failed: {error:?}"
            ));
        }
        let resp_expiration = resp.response.expiration;
        let resp_cred = resp.response.credentials;

        let cred = Credential {
            secret_id: resp_cred.tmp_secret_id,
            secret_key: resp_cred.tmp_secret_key,
            security_token: Some(resp_cred.token),
            expires_in: Some(parse_rfc3339(&resp_expiration)?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Serialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityRequest {
    role_session_name: String,
    web_identity_token: String,
    role_arn: String,
    provider_id: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResult {
    response: AssumeRoleWithWebIdentityResponse,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    error: Option<AssumeRoleWithWebIdentityError>,
    expiration: String,
    credentials: AssumeRoleWithWebIdentityCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityCredentials {
    token: String,
    tmp_secret_id: String,
    tmp_secret_key: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityError {
    code: String,
    message: String,
}
