use crate::Credential;
use async_trait::async_trait;
use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use http::Method;
use reqsign_core::time::{now, parse_rfc3339, DateTime};
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct IMDSv2CredentialProvider {
    disabled: Option<bool>,
    token: Arc<Mutex<(String, DateTime)>>,
}

impl Default for IMDSv2CredentialProvider {
    fn default() -> Self {
        Self {
            disabled: None,
            token: Arc::new(Mutex::new((String::new(), DateTime::default()))),
        }
    }
}

impl IMDSv2CredentialProvider {
    /// Create a new `IMDSv2CredentialProvider` instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable the provider.
    pub fn disabled(mut self) -> Self {
        self.disabled = Some(true);
        self
    }
}

impl IMDSv2CredentialProvider {
    fn get_endpoint(&self, ctx: &Context) -> String {
        ctx.env_vars()
            .get("AWS_EC2_METADATA_SERVICE_ENDPOINT")
            .cloned()
            .unwrap_or_else(|| "http://169.254.169.254".into())
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
            .uri(url)
            .method(Method::PUT)
            .header(CONTENT_LENGTH, "0")
            // 21600s (6h) is recommended by AWS.
            .header("x-aws-ec2-metadata-token-ttl-seconds", "21600")
            .body(Bytes::new())
            .map_err(|e| Error::unexpected("failed to build token request").with_source(e))?;
        let resp = ctx.http_send_as_string(req).await?;
        if resp.status() != http::StatusCode::OK {
            return Err(Error::unexpected(format!(
                "request to AWS EC2 Metadata Services failed: {}",
                resp.body()
            )));
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
        // Check if disabled, first from config, then from environment
        let disabled = self.disabled.unwrap_or_else(|| {
            ctx.env_vars()
                .get("AWS_EC2_METADATA_DISABLED")
                .map(|v| v == "true")
                .unwrap_or(false)
        });

        if disabled {
            return Ok(None);
        }

        let token = self.load_ec2_metadata_token(ctx).await?;

        // List all credentials that node has.
        let endpoint = self.get_endpoint(ctx);
        let url = format!("{}/latest/meta-data/iam/security-credentials/", endpoint);
        let req = http::Request::builder()
            .uri(url)
            .method(Method::GET)
            // 21600s (6h) is recommended by AWS.
            .header("x-aws-ec2-metadata-token", &token)
            .body(Bytes::new())
            .map_err(|e| {
                Error::unexpected("failed to build credentials list request").with_source(e)
            })?;
        let resp = ctx.http_send_as_string(req).await?;
        if resp.status() != http::StatusCode::OK {
            return Err(Error::unexpected(format!(
                "request to AWS EC2 Metadata Services failed: {}",
                resp.body()
            )));
        }

        let profile_name = resp.into_body();

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
                Error::unexpected("failed to build credentials fetch request").with_source(e)
            })?;

        let resp = ctx.http_send_as_string(req).await?;
        if resp.status() != http::StatusCode::OK {
            return Err(Error::unexpected(format!(
                "request to AWS EC2 Metadata Services failed: {}",
                resp.body()
            )));
        }

        let content = resp.into_body();
        let resp: Ec2MetadataIamSecurityCredentials = serde_json::from_str(&content)
            .map_err(|e| Error::unexpected("failed to parse IMDS response").with_source(e))?;
        if resp.code == "AssumeRoleUnauthorizedAccess" {
            return Err(Error::credential_denied(format!(
                "Incorrect IMDS/IAM configuration: [{}] {}. \
                        Hint: Does this role have a trust relationship with EC2?",
                resp.code, resp.message
            )));
        }
        if resp.code != "Success" {
            return Err(Error::credential_invalid(format!(
                "Error retrieving credentials from IMDS: {} {}",
                resp.code, resp.message
            )));
        }

        let cred = Credential {
            access_key_id: resp.access_key_id,
            secret_access_key: resp.secret_access_key,
            session_token: Some(resp.token),
            expires_in: Some(parse_rfc3339(&resp.expiration).map_err(|e| {
                Error::unexpected("failed to parse expiration time").with_source(e)
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
