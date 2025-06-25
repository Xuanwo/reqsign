use log::debug;
use serde::Serialize;

use reqsign_core::{Context, ProvideCredential, Result};

use crate::credential::{Credential, OAuth2Credentials};
use crate::oauth2::{helpers, types::TokenResponse};

/// OAuth2 refresh token request.
#[derive(Serialize)]
struct RefreshTokenRequest {
    grant_type: &'static str,
    refresh_token: String,
    client_id: String,
    client_secret: String,
}


/// AuthorizedUserCredentialProvider exchanges OAuth2 user credentials for access tokens.
#[derive(Debug, Clone)]
pub struct AuthorizedUserCredentialProvider {
    oauth2_credentials: OAuth2Credentials,
}

impl AuthorizedUserCredentialProvider {
    /// Create a new AuthorizedUserCredentialProvider.
    pub fn new(oauth2_credentials: OAuth2Credentials) -> Self {
        Self { oauth2_credentials }
    }
}

#[async_trait::async_trait]
impl ProvideCredential for AuthorizedUserCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        debug!("exchanging refresh token for access token");

        let req_body = RefreshTokenRequest {
            grant_type: "refresh_token",
            refresh_token: self.oauth2_credentials.refresh_token.clone(),
            client_id: self.oauth2_credentials.client_id.clone(),
            client_secret: self.oauth2_credentials.client_secret.clone(),
        };

        // Use the new OAuth2 helper function
        let token_resp: TokenResponse = helpers::oauth2_post(
            ctx,
            "https://oauth2.googleapis.com/token",
            &req_body,
            "application/json",
        )
        .await?;

        // Convert response to Token
        let token = helpers::token_from_response(&token_resp);

        Ok(Some(Credential::with_token(token)))
    }
}
