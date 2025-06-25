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

/// ECS Task Role Credentials Provider
///
/// This provider fetches credentials from the ECS container metadata endpoint.
/// It supports both relative URI (ECS) and full URI (Fargate) modes.
///
/// # Environment Variables
/// - `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`: Relative URI to fetch credentials (ECS)
/// - `AWS_CONTAINER_CREDENTIALS_FULL_URI`: Full URI to fetch credentials (Fargate)
/// - `AWS_CONTAINER_AUTHORIZATION_TOKEN`: Authorization token for the request
/// - `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`: File containing the authorization token
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
                Error::config_invalid(format!("failed to read auth token file: {}", e))
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
            return Ok(format!("{}{}", ECS_METADATA_ENDPOINT, relative_uri));
        }

        Err(Error::config_invalid(
            "neither AWS_CONTAINER_CREDENTIALS_RELATIVE_URI nor AWS_CONTAINER_CREDENTIALS_FULL_URI is set".to_string(),
        ))
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
            .map_err(|e| Error::unexpected(format!("failed to build request: {}", e)))?;

        // Add authorization token if available
        if let Some(token) = self.load_auth_token(ctx).await? {
            req.headers_mut().insert(
                "Authorization",
                HeaderValue::from_str(&token)
                    .map_err(|e| Error::unexpected(format!("invalid auth token: {}", e)))?,
            );
        }

        let resp = ctx
            .http_send(req)
            .await
            .map_err(|e| Error::unexpected(format!("failed to fetch ECS credentials: {}", e)))?;

        if resp.status() != StatusCode::OK {
            return Err(Error::unexpected(format!(
                "ECS metadata endpoint returned status: {}",
                resp.status()
            )));
        }

        let body = resp.into_body();
        let creds: ECSCredentialResponse = serde_json::from_slice(&body)
            .map_err(|e| Error::unexpected(format!("failed to parse ECS credentials: {}", e)))?;

        let expires_in = creds
            .expiration
            .parse()
            .map_err(|e| Error::unexpected(format!("failed to parse expiration time: {}", e)))?;

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
