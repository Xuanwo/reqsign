use crate::provide_credential::utils::parse_imds_error;
use crate::Credential;
use async_trait::async_trait;
use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use http::Method;
use reqsign_core::time::{now, parse_rfc3339, DateTime};
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct IMDSv2CredentialProvider {
    endpoint: Option<String>,
    timeout: Option<Duration>,
    retry_attempts: Option<u32>,
    token: Arc<Mutex<(String, DateTime)>>,
}

impl Default for IMDSv2CredentialProvider {
    fn default() -> Self {
        Self {
            endpoint: None,
            timeout: None,
            retry_attempts: None,
            token: Arc::new(Mutex::new((String::new(), DateTime::default()))),
        }
    }
}

impl IMDSv2CredentialProvider {
    /// Create a new `IMDSv2CredentialProvider` instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the endpoint for the metadata service.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Set the timeout for metadata requests.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the number of retry attempts.
    pub fn with_retry_attempts(mut self, attempts: u32) -> Self {
        self.retry_attempts = Some(attempts);
        self
    }
}

impl IMDSv2CredentialProvider {
    fn get_endpoint(&self, ctx: &Context) -> String {
        // First check configured endpoint, then environment, then default
        self.endpoint.clone().unwrap_or_else(|| {
            ctx.env_vars()
                .get("AWS_EC2_METADATA_SERVICE_ENDPOINT")
                .cloned()
                .unwrap_or_else(|| "http://169.254.169.254".into())
        })
    }

    async fn load_ec2_metadata_token(&self, ctx: &Context) -> Result<String> {
        {
            let (token, expires_in) = self.token.lock().expect("lock poisoned").clone();
            if expires_in > now() {
                return Ok(token);
            }
        }

        let endpoint = self.get_endpoint(ctx);
        let url = format!("{}/latest/api/token", endpoint);
        let req = http::Request::builder()
            .uri(&url)
            .method(Method::PUT)
            .header(CONTENT_LENGTH, "0")
            // 21600s (6h) is recommended by AWS.
            .header("x-aws-ec2-metadata-token-ttl-seconds", "21600")
            .body(Bytes::new())
            .map_err(|e| {
                Error::request_invalid("failed to build IMDS token request")
                    .with_source(e)
                    .with_context(format!("url: {url}"))
            })?;

        let resp = ctx.http_send_as_string(req).await.map_err(|e| {
            Error::unexpected("failed to connect to IMDS")
                .with_source(e)
                .with_context("endpoint: {endpoint}")
                .with_context("hint: check if running on EC2 instance")
                .set_retryable(true)
        })?;

        if resp.status() != http::StatusCode::OK {
            return Err(parse_imds_error(
                "fetch_imds_token",
                resp.status(),
                resp.body(),
            ));
        }
        let ec2_token = resp.into_body();
        // Set expires_in to 10 minutes to enforce re-read.
        let expires_in = now() + chrono::TimeDelta::try_seconds(21600).expect("in bounds")
            - chrono::TimeDelta::try_seconds(600).expect("in bounds");

        {
            *self.token.lock().expect("lock poisoned") = (ec2_token.clone(), expires_in);
        }

        Ok(ec2_token)
    }
}

#[async_trait]
impl ProvideCredential for IMDSv2CredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Check if disabled via environment
        let disabled_env = ctx
            .env_vars()
            .get("AWS_EC2_METADATA_DISABLED")
            .map(|v| v == "true")
            .unwrap_or(false);

        if disabled_env {
            return Ok(None);
        }

        let token = self.load_ec2_metadata_token(ctx).await?;

        // List all credentials that node has.
        let endpoint = self.get_endpoint(ctx);
        let url = format!("{}/latest/meta-data/iam/security-credentials/", endpoint);
        let req = http::Request::builder()
            .uri(&url)
            .method(Method::GET)
            // 21600s (6h) is recommended by AWS.
            .header("x-aws-ec2-metadata-token", &token)
            .body(Bytes::new())
            .map_err(|e| {
                Error::request_invalid("failed to build IMDS credentials list request")
                    .with_source(e)
                    .with_context("url: {url}")
            })?;

        let resp = ctx.http_send_as_string(req).await.map_err(|e| {
            Error::unexpected("failed to list IMDS credentials")
                .with_source(e)
                .with_context("operation: list_instance_profiles")
                .set_retryable(true)
        })?;

        if resp.status() != http::StatusCode::OK {
            return Err(parse_imds_error(
                "list_instance_profiles",
                resp.status(),
                resp.body(),
            ));
        }

        let profile_name = resp.into_body();

        if profile_name.is_empty() {
            return Err(
                Error::config_invalid("no IAM role attached to EC2 instance")
                    .with_context("hint: attach an IAM role to your EC2 instance"),
            );
        }

        // Get the credentials via role_name.
        let endpoint = self.get_endpoint(ctx);
        let url = format!(
            "{}/latest/meta-data/iam/security-credentials/{profile_name}",
            endpoint
        );
        let req = http::Request::builder()
            .uri(url)
            .method(Method::GET)
            // 21600s (6h) is recommended by AWS.
            .header("x-aws-ec2-metadata-token", &token)
            .body(Bytes::new())
            .map_err(|e| {
                Error::request_invalid("failed to build IMDS credentials fetch request")
                    .with_source(e)
                    .with_context(format!("profile: {}", profile_name))
            })?;

        let resp = ctx.http_send_as_string(req).await.map_err(|e| {
            Error::unexpected("failed to fetch IMDS credentials")
                .with_source(e)
                .with_context(format!("profile: {}", profile_name))
                .set_retryable(true)
        })?;

        if resp.status() != http::StatusCode::OK {
            return Err(
                parse_imds_error("fetch_credentials", resp.status(), resp.body())
                    .with_context(format!("profile: {}", profile_name)),
            );
        }

        let content = resp.into_body();
        let resp: Ec2MetadataIamSecurityCredentials =
            serde_json::from_str(&content).map_err(|e| {
                Error::unexpected("failed to parse IMDS credentials response")
                    .with_source(e)
                    .with_context(format!("response_length: {}", content.len()))
                    .with_context(format!("profile: {}", profile_name))
            })?;

        // Check for specific error codes
        match resp.code.as_str() {
            "Success" => {} // Continue processing
            "AssumeRoleUnauthorizedAccess" => {
                return Err(Error::permission_denied(format!(
                    "EC2 instance not authorized to assume role: {}",
                    resp.message
                ))
                .with_context(format!("error_code: {}", resp.code))
                .with_context(format!("profile: {}", profile_name))
                .with_context("hint: check if the IAM role has a trust relationship with EC2"));
            }
            code if code.contains("Expired") => {
                return Err(Error::credential_invalid(format!(
                    "IMDS credentials expired: {}",
                    resp.message
                ))
                .with_context(format!("error_code: {}", resp.code))
                .with_context(format!("profile: {}", profile_name)));
            }
            _ => {
                return Err(Error::unexpected(format!(
                    "IMDS returned error: [{}] {}",
                    resp.code, resp.message
                ))
                .with_context(format!("profile: {}", profile_name)));
            }
        }

        let cred = Credential {
            access_key_id: resp.access_key_id,
            secret_access_key: resp.secret_access_key,
            session_token: Some(resp.token),
            expires_in: Some(parse_rfc3339(&resp.expiration).map_err(|e| {
                Error::unexpected("failed to parse IMDS credential expiration time")
                    .with_source(e)
                    .with_context(format!("expiration_value: {}", resp.expiration))
            })?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct Ec2MetadataIamSecurityCredentials {
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: String,

    code: String,
    message: String,
}
