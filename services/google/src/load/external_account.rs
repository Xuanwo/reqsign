use std::time::Duration;

use anyhow::{bail, Result};
use http::header::{ACCEPT, CONTENT_TYPE};
use log::{debug, error};
use serde::{Deserialize, Serialize};

use reqsign_core::{time::now, Context, Load};

use crate::config::Config;
use crate::key::{
    CredentialSource, ExternalAccount, FileSourcedCredential, Token, UrlSourcedCredential,
};

/// The maximum impersonated token lifetime allowed, 1 hour.
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// STS token response.
#[derive(Deserialize)]
struct StsTokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

/// Impersonated token response.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImpersonatedTokenResponse {
    access_token: String,
    expire_time: String,
}

/// STS token exchange request.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StsTokenRequest {
    grant_type: &'static str,
    requested_token_type: &'static str,
    audience: String,
    scope: &'static str,
    subject_token: String,
    subject_token_type: String,
}

/// Impersonation request.
#[derive(Serialize)]
struct ImpersonationRequest {
    scope: Vec<String>,
    lifetime: String,
}

/// ExternalAccountLoader exchanges external account credentials for access tokens.
#[derive(Debug, Clone)]
pub struct ExternalAccountLoader {
    config: Config,
    external_account: ExternalAccount,
}

impl ExternalAccountLoader {
    /// Create a new ExternalAccountLoader.
    pub fn new(config: Config, external_account: ExternalAccount) -> Self {
        Self {
            config,
            external_account,
        }
    }

    async fn load_oidc_token(&self, ctx: &Context) -> Result<String> {
        match &self.external_account.credential_source {
            CredentialSource::FileSourced(source) => {
                self.load_file_sourced_token(ctx, source).await
            }
            CredentialSource::UrlSourced(source) => self.load_url_sourced_token(ctx, source).await,
        }
    }

    async fn load_file_sourced_token(
        &self,
        ctx: &Context,
        source: &FileSourcedCredential,
    ) -> Result<String> {
        debug!("loading OIDC token from file: {}", source.file);
        let content = ctx.file_read(&source.file).await?;
        source.format.parse(&content)
    }

    async fn load_url_sourced_token(
        &self,
        ctx: &Context,
        source: &UrlSourcedCredential,
    ) -> Result<String> {
        debug!("loading OIDC token from URL: {}", source.url);

        let mut req = http::Request::get(&source.url);

        // Add custom headers if any
        if let Some(headers) = &source.headers {
            for (key, value) in headers {
                req = req.header(key, value);
            }
        }

        let resp = ctx.http_send(req.body(Vec::<u8>::new().into())?).await?;

        if resp.status() != http::StatusCode::OK {
            error!("exchange token got unexpected response: {:?}", resp);
            let body = String::from_utf8_lossy(resp.body());
            bail!("exchange OIDC token failed: {}", body);
        }

        source.format.parse(resp.body())
    }

    async fn exchange_sts_token(&self, ctx: &Context, oidc_token: &str) -> Result<Token> {
        debug!("exchanging OIDC token for STS access token");

        let request = StsTokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
            requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
            audience: self.external_account.audience.clone(),
            scope: "https://www.googleapis.com/auth/cloud-platform",
            subject_token: oidc_token.to_string(),
            subject_token_type: self.external_account.subject_token_type.clone(),
        };

        let body = serde_json::to_vec(&request)?;

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(&self.external_account.token_url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .body(body.into())?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            error!("exchange token got unexpected response: {:?}", resp);
            let body = String::from_utf8_lossy(resp.body());
            bail!("exchange token failed: {}", body);
        }

        let token_resp: StsTokenResponse = serde_json::from_slice(resp.body())?;

        let expires_at = token_resp.expires_in.map(|expires_in| {
            now() + chrono::TimeDelta::try_seconds(expires_in as i64).expect("in bounds")
        });

        Ok(Token {
            access_token: token_resp.access_token,
            expires_at,
        })
    }

    async fn impersonate_service_account(
        &self,
        ctx: &Context,
        access_token: &str,
    ) -> Result<Option<Token>> {
        let Some(url) = &self.external_account.service_account_impersonation_url else {
            return Ok(None);
        };

        debug!("impersonating service account");

        let scope = self.config.scope.as_ref().ok_or_else(|| {
            anyhow::anyhow!("scope is required for service account impersonation")
        })?;

        let lifetime = self
            .external_account
            .service_account_impersonation
            .as_ref()
            .and_then(|s| s.token_lifetime_seconds)
            .unwrap_or(MAX_LIFETIME.as_secs() as usize);

        let request = ImpersonationRequest {
            scope: vec![scope.clone()],
            lifetime: format!("{lifetime}s"),
        };

        let body = serde_json::to_vec(&request)?;

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header("Authorization", format!("Bearer {}", access_token))
            .body(body.into())?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            error!("impersonated token got unexpected response: {:?}", resp);
            let body = String::from_utf8_lossy(resp.body());
            bail!("exchange impersonated token failed: {}", body);
        }

        let token_resp: ImpersonatedTokenResponse = serde_json::from_slice(resp.body())?;

        // Parse expire time from RFC3339 format
        let expires_at = chrono::DateTime::parse_from_rfc3339(&token_resp.expire_time)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc));

        Ok(Some(Token {
            access_token: token_resp.access_token,
            expires_at,
        }))
    }
}

#[async_trait::async_trait]
impl Load for ExternalAccountLoader {
    type Key = Token;

    async fn load(&self, ctx: &Context) -> Result<Option<Self::Key>> {
        // Load OIDC token from source
        let oidc_token = self.load_oidc_token(ctx).await?;

        // Exchange for STS token
        let sts_token = self.exchange_sts_token(ctx, &oidc_token).await?;

        // Try to impersonate service account if configured
        if let Some(token) = self
            .impersonate_service_account(ctx, &sts_token.access_token)
            .await?
        {
            Ok(Some(token))
        } else {
            Ok(Some(sts_token))
        }
    }
}
