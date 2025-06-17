use anyhow::{bail, Result};
use http::header;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use log::{debug, error};
use serde::{Deserialize, Serialize};

use reqsign_core::{time::now, Context, ProvideCredential};

use crate::config::Config;
use crate::credential::{ServiceAccount, Token};

/// Claims is used to build JWT for Google Cloud.
#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

impl Claims {
    fn new(client_email: &str, scope: &str) -> Self {
        let current = now().timestamp() as u64;

        Claims {
            iss: client_email.to_string(),
            scope: scope.to_string(),
            aud: "https://oauth2.googleapis.com/token".to_string(),
            exp: current + 3600,
            iat: current,
        }
    }
}

/// OAuth2 token response.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// ServiceAccountLoader exchanges service account credentials for access tokens.
#[derive(Debug, Clone)]
pub struct ServiceAccountLoader {
    config: Config,
    service_account: ServiceAccount,
}

impl ServiceAccountLoader {
    /// Create a new ServiceAccountLoader.
    pub fn new(config: Config, service_account: ServiceAccount) -> Self {
        Self {
            config,
            service_account,
        }
    }
}

#[async_trait::async_trait]
impl ProvideCredential for ServiceAccountLoader {
    type Credential = Token;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let scope = self
            .config
            .scope
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("scope is required for service account"))?;

        debug!("exchanging service account for token with scope: {}", scope);

        // Create JWT
        let jwt = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &Claims::new(&self.service_account.client_email, scope),
            &EncodingKey::from_rsa_pem(self.service_account.private_key.as_bytes())?,
        )?;

        // Exchange JWT for access token
        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={}",
            jwt
        );
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://oauth2.googleapis.com/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.into_bytes().into())?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            error!("exchange token got unexpected response: {:?}", resp);
            let body = String::from_utf8_lossy(resp.body());
            bail!("exchange token failed: {}", body);
        }

        let token_resp: TokenResponse = serde_json::from_slice(resp.body())?;

        let expires_at = token_resp.expires_in.map(|expires_in| {
            now() + chrono::TimeDelta::try_seconds(expires_in as i64).expect("in bounds")
        });

        Ok(Some(Token {
            access_token: token_resp.access_token,
            expires_at,
        }))
    }
}
