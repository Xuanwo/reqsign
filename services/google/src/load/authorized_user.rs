use anyhow::{bail, Result};
use http::header::CONTENT_TYPE;
use log::{debug, error};
use serde::{Deserialize, Serialize};

use reqsign_core::{time::now, Context, ProvideCredential};

use crate::config::Config;
use crate::credential::{Credential, OAuth2Credentials, Token};

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
}

/// AuthorizedUserLoader exchanges OAuth2 user credentials for access tokens.
#[derive(Debug, Clone)]
pub struct AuthorizedUserLoader {
    oauth2_credentials: OAuth2Credentials,
}

impl AuthorizedUserLoader {
    /// Create a new AuthorizedUserLoader.
    pub fn new(_config: Config, oauth2_credentials: OAuth2Credentials) -> Self {
        Self { oauth2_credentials }
    }
}

#[async_trait::async_trait]
impl ProvideCredential for AuthorizedUserLoader {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        debug!("exchanging refresh token for access token");

        let req_body = RefreshTokenRequest {
            grant_type: "refresh_token",
            refresh_token: self.oauth2_credentials.refresh_token.clone(),
            client_id: self.oauth2_credentials.client_id.clone(),
            client_secret: self.oauth2_credentials.client_secret.clone(),
        };

        let body = serde_json::to_vec(&req_body)?;
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://oauth2.googleapis.com/token")
            .header(CONTENT_TYPE, "application/json")
            .body(body.into())?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            error!("refresh token exchange got unexpected response: {:?}", resp);
            let body = String::from_utf8_lossy(resp.body());
            bail!("refresh token exchange failed: {}", body);
        }

        let token_resp: RefreshTokenResponse = serde_json::from_slice(resp.body())?;

        let expires_at = token_resp.expires_in.map(|expires_in| {
            now() + chrono::TimeDelta::try_seconds(expires_in as i64).expect("in bounds")
        });

        let token = Token {
            access_token: token_resp.access_token,
            expires_at,
        };

        Ok(Some(Credential::with_token(token)))
    }
}
