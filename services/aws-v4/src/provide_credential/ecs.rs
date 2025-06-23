use crate::constants::{
    AWS_CONTAINER_CREDENTIALS_FULL_URI, AWS_CONTAINER_CREDENTIALS_RELATIVE_URI,
};
use crate::{Config, Credential};
use async_trait::async_trait;
use bytes::Bytes;
use http::Method;
use reqsign_core::time::parse_rfc3339;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;
use std::sync::Arc;

/// EcsCredentialProvider will load credential from ECS task metadata endpoint.
///
/// ECS credential provider provides credentials for ECS tasks using
/// the AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or AWS_CONTAINER_CREDENTIALS_FULL_URI
/// environment variables.
///
/// References:
/// - [IAM roles for tasks](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)
#[derive(Debug)]
pub struct EcsCredentialProvider {
    config: Arc<Config>,
}

impl EcsCredentialProvider {
    /// Create a new `EcsCredentialProvider` instance.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

impl Default for EcsCredentialProvider {
    fn default() -> Self {
        Self::new(Arc::new(Config::default()))
    }
}

#[async_trait]
impl ProvideCredential for EcsCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // If container_credentials_disabled is set, return None.
        if self.config.container_credentials_disabled {
            return Ok(None);
        }

        let envs = ctx.env_vars();

        // Check if we're in an ECS environment
        let relative_uri = envs.get(AWS_CONTAINER_CREDENTIALS_RELATIVE_URI);
        let full_uri = envs.get(AWS_CONTAINER_CREDENTIALS_FULL_URI);

        let url = match (relative_uri, full_uri) {
            (Some(relative), _) => {
                // Use relative URI with the standard metadata endpoint
                format!("http://169.254.170.2{}", relative)
            }
            (None, Some(full)) => {
                // Use full URI directly
                full.to_string()
            }
            (None, None) => {
                // Not in an ECS environment
                return Ok(None);
            }
        };

        // Make request to ECS metadata endpoint
        let req = http::Request::builder()
            .uri(&url)
            .method(Method::GET)
            .body(Bytes::new())
            .map_err(|e| {
                Error::unexpected("failed to build ECS metadata request").with_source(e)
            })?;

        let resp = ctx.http_send_as_string(req).await?;

        if resp.status() != http::StatusCode::OK {
            return Err(Error::unexpected(format!(
                "request to ECS task metadata endpoint failed: status={}, body={}",
                resp.status(),
                resp.body()
            )));
        }

        let content = resp.into_body();
        let cred: EcsTaskCredentials = serde_json::from_str(&content).map_err(|e| {
            Error::unexpected("failed to parse ECS task credentials").with_source(e)
        })?;

        let expires_in = parse_rfc3339(&cred.expiration)
            .map_err(|e| Error::unexpected("failed to parse expiration time").with_source(e))?;

        Ok(Some(Credential {
            access_key_id: cred.access_key_id,
            secret_access_key: cred.secret_access_key,
            session_token: Some(cred.token),
            expires_in: Some(expires_in),
        }))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EcsTaskCredentials {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,
    #[serde(rename = "Token")]
    token: String,
    #[serde(rename = "Expiration")]
    expiration: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::StaticEnv;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_ecs_credential_provider_without_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let provider = EcsCredentialProvider::new(Arc::new(Config::default()));
        let result = provider.provide_credential(&ctx).await.unwrap();
        assert!(result.is_none());
    }
}
