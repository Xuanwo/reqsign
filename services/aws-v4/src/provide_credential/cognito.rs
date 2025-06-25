use crate::Credential;
use async_trait::async_trait;
use chrono::DateTime;
use http::{Method, Request, StatusCode};
use log::debug;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;
use serde_json::json;

/// Cognito Identity Credentials Provider
///
/// This provider fetches temporary AWS credentials using Amazon Cognito Identity.
/// It's typically used for mobile and web applications that need temporary AWS access.
///
/// # Requirements
/// - A Cognito Identity Pool ID
/// - Optional: Identity token from a supported identity provider (Facebook, Google, etc.)
///
/// # Usage
/// ```rust,no_run
/// use reqsign_aws_v4::CognitoIdentityCredentialProvider;
///
/// let provider = CognitoIdentityCredentialProvider::new()
///     .with_identity_pool_id("us-east-1:12345678-1234-1234-1234-123456789012")
///     .with_region("us-east-1");
/// ```
#[derive(Debug, Clone)]
pub struct CognitoIdentityCredentialProvider {
    identity_pool_id: Option<String>,
    region: Option<String>,
    identity_id: Option<String>,
    logins: Option<std::collections::HashMap<String, String>>,
}

impl Default for CognitoIdentityCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CognitoIdentityCredentialProvider {
    /// Create a new Cognito Identity credential provider
    pub fn new() -> Self {
        Self {
            identity_pool_id: None,
            region: None,
            identity_id: None,
            logins: None,
        }
    }

    /// Set the Cognito Identity Pool ID
    pub fn with_identity_pool_id(mut self, pool_id: impl Into<String>) -> Self {
        self.identity_pool_id = Some(pool_id.into());
        self
    }

    /// Set the AWS region
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Set a specific identity ID (if already known)
    pub fn with_identity_id(mut self, identity_id: impl Into<String>) -> Self {
        self.identity_id = Some(identity_id.into());
        self
    }

    /// Add login tokens from identity providers
    pub fn with_logins(mut self, logins: std::collections::HashMap<String, String>) -> Self {
        self.logins = Some(logins);
        self
    }

    /// Get or create an identity ID
    async fn get_identity_id(&self, ctx: &Context) -> Result<String> {
        if let Some(id) = &self.identity_id {
            return Ok(id.clone());
        }

        let pool_id = self
            .identity_pool_id
            .as_ref()
            .ok_or_else(|| Error::config_invalid("identity_pool_id is required".to_string()))?;

        let region = self
            .region
            .as_ref()
            .ok_or_else(|| Error::config_invalid("region is required".to_string()))?;

        let endpoint = format!("https://cognito-identity.{}.amazonaws.com/", region);

        let body = if let Some(logins) = &self.logins {
            json!({
                "IdentityPoolId": pool_id,
                "Logins": logins
            })
        } else {
            json!({
                "IdentityPoolId": pool_id
            })
        };

        let req = Request::builder()
            .method(Method::POST)
            .uri(&endpoint)
            .header("x-amz-target", "AWSCognitoIdentityService.GetId")
            .header("content-type", "application/x-amz-json-1.1")
            .body(bytes::Bytes::from(serde_json::to_vec(&body).map_err(
                |e| Error::unexpected(format!("failed to serialize request body: {}", e)),
            )?))
            .map_err(|e| Error::unexpected(format!("failed to build request: {}", e)))?;

        let resp = ctx
            .http_send(req)
            .await
            .map_err(|e| Error::unexpected(format!("failed to get identity ID: {}", e)))?;

        if resp.status() != StatusCode::OK {
            return Err(Error::unexpected(format!(
                "Cognito GetId returned status: {}",
                resp.status()
            )));
        }

        let body = resp.into_body();
        let result: GetIdResponse = serde_json::from_slice(&body)
            .map_err(|e| Error::unexpected(format!("failed to parse GetId response: {}", e)))?;

        Ok(result.identity_id)
    }

    /// Get credentials for an identity
    async fn get_credentials_for_identity(
        &self,
        ctx: &Context,
        identity_id: &str,
    ) -> Result<Credential> {
        let region = self
            .region
            .as_ref()
            .ok_or_else(|| Error::config_invalid("region is required".to_string()))?;

        let endpoint = format!("https://cognito-identity.{}.amazonaws.com/", region);

        let body = if let Some(logins) = &self.logins {
            json!({
                "IdentityId": identity_id,
                "Logins": logins
            })
        } else {
            json!({
                "IdentityId": identity_id
            })
        };

        let req = Request::builder()
            .method(Method::POST)
            .uri(&endpoint)
            .header(
                "x-amz-target",
                "AWSCognitoIdentityService.GetCredentialsForIdentity",
            )
            .header("content-type", "application/x-amz-json-1.1")
            .body(bytes::Bytes::from(serde_json::to_vec(&body).map_err(
                |e| Error::unexpected(format!("failed to serialize request body: {}", e)),
            )?))
            .map_err(|e| Error::unexpected(format!("failed to build request: {}", e)))?;

        let resp = ctx
            .http_send(req)
            .await
            .map_err(|e| Error::unexpected(format!("failed to get credentials: {}", e)))?;

        if resp.status() != StatusCode::OK {
            return Err(Error::unexpected(format!(
                "Cognito GetCredentialsForIdentity returned status: {}",
                resp.status()
            )));
        }

        let body = resp.into_body();
        let result: GetCredentialsResponse = serde_json::from_slice(&body).map_err(|e| {
            Error::unexpected(format!("failed to parse credentials response: {}", e))
        })?;

        let creds = result.credentials;
        let expires_in = DateTime::from_timestamp(creds.expiration, 0)
            .ok_or_else(|| Error::unexpected("invalid expiration timestamp".to_string()))?;

        Ok(Credential {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_key,
            session_token: Some(creds.session_token),
            expires_in: Some(expires_in),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetIdResponse {
    identity_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetCredentialsResponse {
    credentials: CognitoCredentials,
    #[allow(dead_code)]
    identity_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CognitoCredentials {
    access_key_id: String,
    secret_key: String,
    session_token: String,
    expiration: i64,
}

#[async_trait]
impl ProvideCredential for CognitoIdentityCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        if self.identity_pool_id.is_none() {
            debug!("Cognito Identity: no identity pool ID configured");
            return Ok(None);
        }

        // Get or create identity ID
        let identity_id = self.get_identity_id(ctx).await?;
        debug!("Cognito Identity: using identity ID: {}", identity_id);

        // Get credentials for the identity
        let creds = self.get_credentials_for_identity(ctx, &identity_id).await?;

        Ok(Some(creds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;

    #[tokio::test]
    async fn test_cognito_provider_no_config() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let provider = CognitoIdentityCredentialProvider::new();
        let result = provider.provide_credential(&ctx).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cognito_provider_builder() {
        let provider = CognitoIdentityCredentialProvider::new()
            .with_identity_pool_id("us-east-1:12345678-1234-1234-1234-123456789012")
            .with_region("us-east-1");

        assert_eq!(
            provider.identity_pool_id,
            Some("us-east-1:12345678-1234-1234-1234-123456789012".to_string())
        );
        assert_eq!(provider.region, Some("us-east-1".to_string()));
    }
}
