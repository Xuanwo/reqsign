use std::time::Duration;

use anyhow::{bail, Result};
use http::header::CONTENT_TYPE;
use log::{debug, error};
use serde::{Deserialize, Serialize};

use reqsign_core::{time::now, Context, Load};

use crate::config::Config;
use crate::key::{ImpersonatedServiceAccount, Token};

/// The maximum impersonated token lifetime allowed, 1 hour.
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// OAuth2 refresh token request.
#[derive(Serialize)]
struct RefreshTokenRequest {
    grant_type: &'static str,
    refresh_token: String,
    client_id: String,
    client_secret: String,
}

/// OAuth2 token response.
#[derive(Deserialize)]
struct RefreshTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    scope: Option<String>,
}

/// Impersonation request.
#[derive(Serialize)]
struct ImpersonationRequest {
    lifetime: String,
    scope: Vec<String>,
    delegates: Vec<String>,
}

/// Impersonated token response.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImpersonatedTokenResponse {
    access_token: String,
    expire_time: String,
}

/// ImpersonatedServiceAccountLoader exchanges impersonated service account credentials for access tokens.
#[derive(Debug, Clone)]
pub struct ImpersonatedServiceAccountLoader {
    config: Config,
    impersonated_service_account: ImpersonatedServiceAccount,
}

impl ImpersonatedServiceAccountLoader {
    /// Create a new ImpersonatedServiceAccountLoader.
    pub fn new(config: Config, impersonated_service_account: ImpersonatedServiceAccount) -> Self {
        Self {
            config,
            impersonated_service_account,
        }
    }

    async fn generate_bearer_auth_token(&self, ctx: &Context) -> Result<Token> {
        debug!("refreshing OAuth2 token for impersonated service account");

        let request = RefreshTokenRequest {
            grant_type: "refresh_token",
            refresh_token: self
                .impersonated_service_account
                .source_credentials
                .refresh_token
                .clone(),
            client_id: self
                .impersonated_service_account
                .source_credentials
                .client_id
                .clone(),
            client_secret: self
                .impersonated_service_account
                .source_credentials
                .client_secret
                .clone(),
        };

        let body = serde_json::to_vec(&request)?;

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://oauth2.googleapis.com/token")
            .header(CONTENT_TYPE, "application/json")
            .body(body.into())?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            error!(
                "bearer token loader for impersonated service account got unexpected response: {:?}",
                resp
            );
            let body = String::from_utf8_lossy(resp.body());
            bail!(
                "bearer token loader for impersonated service account failed: {}",
                body
            );
        }

        let token_resp: RefreshTokenResponse = serde_json::from_slice(resp.body())?;

        let expires_at = token_resp.expires_in.map(|expires_in| {
            now() + chrono::TimeDelta::try_seconds(expires_in as i64).expect("in bounds")
        });

        Ok(Token {
            access_token: token_resp.access_token,
            expires_at,
        })
    }

    async fn generate_access_token(&self, ctx: &Context, bearer_token: &Token) -> Result<Token> {
        debug!("generating access token for impersonated service account");

        let scope =
            self.config.scope.as_ref().ok_or_else(|| {
                anyhow::anyhow!("scope is required for impersonated service account")
            })?;

        let request = ImpersonationRequest {
            lifetime: format!("{}s", MAX_LIFETIME.as_secs()),
            scope: vec![scope.clone()],
            delegates: self.impersonated_service_account.delegates.clone(),
        };

        let body = serde_json::to_vec(&request)?;

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(
                &self
                    .impersonated_service_account
                    .service_account_impersonation_url,
            )
            .header(CONTENT_TYPE, "application/json")
            .header(
                "Authorization",
                format!("Bearer {}", bearer_token.access_token),
            )
            .body(body.into())?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            error!(
                "access token loader for impersonated service account got unexpected response: {:?}",
                resp
            );
            let body = String::from_utf8_lossy(resp.body());
            bail!(
                "access token loader for impersonated service account failed: {}",
                body
            );
        }

        let token_resp: ImpersonatedTokenResponse = serde_json::from_slice(resp.body())?;

        // Parse expire time from RFC3339 format
        let expires_at = chrono::DateTime::parse_from_rfc3339(&token_resp.expire_time)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc));

        Ok(Token {
            access_token: token_resp.access_token,
            expires_at,
        })
    }
}

#[async_trait::async_trait]
impl Load for ImpersonatedServiceAccountLoader {
    type Key = Token;

    async fn load(&self, ctx: &Context) -> Result<Option<Self::Key>> {
        // First get bearer token using OAuth2 refresh
        let bearer_token = self.generate_bearer_auth_token(ctx).await?;

        // Then exchange for impersonated access token
        let access_token = self.generate_access_token(ctx, &bearer_token).await?;

        Ok(Some(access_token))
    }
}
