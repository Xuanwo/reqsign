use crate::Credential;
use async_trait::async_trait;
use http::{HeaderValue, Method, Request, StatusCode};
use log::debug;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;

const AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: &str = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
const AWS_CONTAINER_CREDENTIALS_FULL_URI: &str = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
const AWS_CONTAINER_AUTHORIZATION_TOKEN: &str = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
const AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: &str = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE";
const ECS_METADATA_ENDPOINT: &str = "http://169.254.170.2";
const ECS_CONTAINER_METADATA_URI: &str = "ECS_CONTAINER_METADATA_URI";

/// ECS Task Role Credentials Provider
///
/// This provider fetches IAM credentials from the ECS Task IAM Roles endpoint.
/// It supports both relative URI (ECS) and full URI (Fargate) modes.
///
/// # Important Note
/// This provider fetches IAM **credentials**, not task metadata. The credentials
/// endpoint is separate from the task metadata endpoints (v2/v3/v4). While metadata
/// endpoints provide information about the task and container, the credentials
/// endpoint provides IAM role credentials for authentication.
///
/// # Environment Variables
/// - `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`: Relative URI to fetch credentials (ECS)
/// - `AWS_CONTAINER_CREDENTIALS_FULL_URI`: Full URI to fetch credentials (Fargate)
/// - `AWS_CONTAINER_AUTHORIZATION_TOKEN`: Authorization token for the request
/// - `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`: File containing the authorization token
/// - `ECS_CONTAINER_METADATA_URI`: Override the default base endpoint (for testing)
#[derive(Debug, Clone)]
pub struct ECSCredentialProvider {
    endpoint: Option<String>,
    auth_token: Option<String>,
}

impl Default for ECSCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ECSCredentialProvider {
    /// Create a new ECS credential provider
    pub fn new() -> Self {
        Self {
            endpoint: None,
            auth_token: None,
        }
    }

    /// Create with custom endpoint
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Create with custom auth token
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    async fn load_auth_token(&self, ctx: &Context) -> Result<Option<String>> {
        // If auth token is already set, use it
        if let Some(token) = &self.auth_token {
            return Ok(Some(token.clone()));
        }

        // Try to get token from environment
        if let Some(token) = ctx.env_var(AWS_CONTAINER_AUTHORIZATION_TOKEN) {
            return Ok(Some(token));
        }

        // Try to get token from file
        if let Some(token_file) = ctx.env_var(AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE) {
            let token = ctx.file_read(&token_file).await.map_err(|e| {
                Error::config_invalid("failed to read ECS auth token file")
                    .with_source(e)
                    .with_context(format!("file: {}", token_file))
            })?;
            return Ok(Some(String::from_utf8_lossy(&token).trim().to_string()));
        }

        Ok(None)
    }

    fn get_endpoint(&self, ctx: &Context) -> Result<String> {
        // Use custom endpoint if provided
        if let Some(endpoint) = &self.endpoint {
            return Ok(endpoint.clone());
        }

        // Try full URI first (Fargate)
        if let Some(full_uri) = ctx.env_var(AWS_CONTAINER_CREDENTIALS_FULL_URI) {
            return Ok(full_uri);
        }

        // Try relative URI (ECS)
        if let Some(relative_uri) = ctx.env_var(AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) {
            // Allow override of metadata endpoint for testing
            let base_endpoint = ctx
                .env_var(ECS_CONTAINER_METADATA_URI)
                .unwrap_or_else(|| ECS_METADATA_ENDPOINT.to_string());
            return Ok(format!("{base_endpoint}{relative_uri}"));
        }

        Err(Error::config_invalid(
            "ECS container credentials endpoint not configured"
        )
        .with_context("hint: set AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or AWS_CONTAINER_CREDENTIALS_FULL_URI")
        .with_context("note: are you running on ECS or Fargate?"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ECSCredentialResponse {
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: String,
}

#[async_trait]
impl ProvideCredential for ECSCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let endpoint = match self.get_endpoint(ctx) {
            Ok(ep) => ep,
            Err(_) => {
                debug!("ECS credential provider: no container credentials endpoint found");
                return Ok(None);
            }
        };

        debug!(
            "ECS credential provider: fetching credentials from {}",
            endpoint
        );

        let mut req = Request::builder()
            .method(Method::GET)
            .uri(&endpoint)
            .body(bytes::Bytes::new())
            .map_err(|e| {
                Error::request_invalid("failed to build ECS credentials request")
                    .with_source(e)
                    .with_context(format!("endpoint: {}", endpoint))
            })?;

        // Add authorization token if available
        if let Some(token) = self.load_auth_token(ctx).await? {
            req.headers_mut().insert(
                "Authorization",
                HeaderValue::from_str(&token).map_err(|e| {
                    Error::config_invalid("invalid ECS authorization token")
                        .with_source(e)
                        .with_context("token_source: environment or file")
                })?,
            );
        }

        let resp = ctx.http_send(req).await.map_err(|e| {
            Error::unexpected("failed to fetch ECS credentials")
                .with_source(e)
                .with_context(format!("endpoint: {}", endpoint))
                .with_context("hint: check if running on ECS/Fargate with proper IAM role")
                .set_retryable(true)
        })?;

        if resp.status() != StatusCode::OK {
            let status = resp.status();
            let body = String::from_utf8_lossy(resp.body());

            let error = match status.as_u16() {
                401 | 403 => Error::permission_denied(format!(
                    "ECS task not authorized to fetch credentials: {}",
                    body
                ))
                .with_context("hint: check if task has proper IAM role attached"),
                404 => Error::config_invalid("ECS credentials endpoint not found")
                    .with_context(format!("endpoint: {}", endpoint))
                    .with_context("hint: verify the container credentials URI"),
                500..=599 => Error::unexpected(format!("ECS metadata service error: {}", body))
                    .set_retryable(true),
                _ => Error::unexpected(format!(
                    "ECS metadata endpoint returned unexpected status {}: {}",
                    status, body
                )),
            };

            return Err(error
                .with_context(format!("http_status: {}", status))
                .with_context(format!("endpoint: {}", endpoint)));
        }

        let body = resp.into_body();
        let creds: ECSCredentialResponse = serde_json::from_slice(&body).map_err(|e| {
            Error::unexpected("failed to parse ECS credentials response")
                .with_source(e)
                .with_context(format!("response_length: {}", body.len()))
                .with_context(format!("endpoint: {}", endpoint))
        })?;

        let expires_in = creds.expiration.parse().map_err(|e| {
            Error::unexpected("failed to parse ECS credential expiration")
                .with_source(e)
                .with_context(format!("expiration_value: {}", creds.expiration))
        })?;

        Ok(Some(Credential {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: Some(creds.token),
            expires_in: Some(expires_in),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::StaticEnv;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_ecs_provider_no_env() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let provider = ECSCredentialProvider::new();
        let result = provider.provide_credential(&ctx).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_endpoint_relative_uri() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([(
                AWS_CONTAINER_CREDENTIALS_RELATIVE_URI.to_string(),
                "/v2/credentials/task-role".to_string(),
            )]),
        });

        let provider = ECSCredentialProvider::new();
        let endpoint = provider.get_endpoint(&ctx).unwrap();
        assert_eq!(endpoint, "http://169.254.170.2/v2/credentials/task-role");
    }

    #[tokio::test]
    async fn test_get_endpoint_relative_uri_with_custom_base() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (
                    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI.to_string(),
                    "/creds".to_string(),
                ),
                (
                    ECS_CONTAINER_METADATA_URI.to_string(),
                    "http://localhost:51679".to_string(),
                ),
            ]),
        });

        let provider = ECSCredentialProvider::new();
        let endpoint = provider.get_endpoint(&ctx).unwrap();
        assert_eq!(endpoint, "http://localhost:51679/creds");
    }

    #[tokio::test]
    async fn test_get_endpoint_full_uri() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([(
                AWS_CONTAINER_CREDENTIALS_FULL_URI.to_string(),
                "http://localhost:8080/credentials".to_string(),
            )]),
        });

        let provider = ECSCredentialProvider::new();
        let endpoint = provider.get_endpoint(&ctx).unwrap();
        assert_eq!(endpoint, "http://localhost:8080/credentials");
    }

    #[tokio::test]
    async fn test_custom_endpoint() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let provider = ECSCredentialProvider::new().with_endpoint("http://custom-endpoint/creds");

        let endpoint = provider.get_endpoint(&ctx).unwrap();
        assert_eq!(endpoint, "http://custom-endpoint/creds");
    }
}
