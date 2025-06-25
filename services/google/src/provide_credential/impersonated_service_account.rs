use std::time::Duration;

use log::debug;
use serde::Serialize;

use reqsign_core::{Context, ProvideCredential, Result};

use crate::credential::{Credential, ImpersonatedServiceAccount};
use crate::oauth2::{helpers, types::{TokenResponse, ImpersonatedTokenResponse}};

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


/// Impersonation request.
#[derive(Serialize)]
struct ImpersonationRequest {
    lifetime: String,
    scope: Vec<String>,
    delegates: Vec<String>,
}


/// ImpersonatedServiceAccountCredentialProvider exchanges impersonated service account credentials for access tokens.
#[derive(Debug, Clone)]
pub struct ImpersonatedServiceAccountCredentialProvider {
    impersonated_service_account: ImpersonatedServiceAccount,
    scope: Option<String>,
}

impl ImpersonatedServiceAccountCredentialProvider {
    /// Create a new ImpersonatedServiceAccountCredentialProvider.
    pub fn new(impersonated_service_account: ImpersonatedServiceAccount) -> Self {
        Self {
            impersonated_service_account,
            scope: None,
        }
    }

    /// Set the OAuth2 scope.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    async fn generate_bearer_auth_token(&self, ctx: &Context) -> Result<crate::credential::Token> {
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

        // Use the new OAuth2 helper function
        let token_resp: TokenResponse = helpers::oauth2_post(
            ctx,
            "https://oauth2.googleapis.com/token",
            &request,
            "application/json",
        )
        .await?;

        // Convert response to Token
        Ok(helpers::token_from_response(&token_resp))
    }

    async fn generate_access_token(&self, ctx: &Context, bearer_token: &crate::credential::Token) -> Result<crate::credential::Token> {
        debug!("generating access token for impersonated service account");

        let scope = self
            .scope
            .clone()
            .or_else(|| ctx.env_var(crate::constants::GOOGLE_SCOPE))
            .unwrap_or_else(|| crate::constants::DEFAULT_SCOPE.to_string());

        let request = ImpersonationRequest {
            lifetime: format!("{}s", MAX_LIFETIME.as_secs()),
            scope: vec![scope.clone()],
            delegates: self.impersonated_service_account.delegates.clone(),
        };

        // Use the new OAuth2 helper function with authorization
        let token_resp: ImpersonatedTokenResponse = helpers::oauth2_post_with_auth(
            ctx,
            &self
                .impersonated_service_account
                .service_account_impersonation_url,
            &request,
            "application/json",
            Some(&format!("Bearer {}", bearer_token.access_token)),
        )
        .await?;

        // Parse expire time from RFC3339 format
        let expires_at = helpers::parse_rfc3339_expiration(&token_resp.expire_time)?;

        Ok(crate::credential::Token {
            access_token: token_resp.access_token,
            expires_at,
        })
    }
}

#[async_trait::async_trait]
impl ProvideCredential for ImpersonatedServiceAccountCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // First get bearer token using OAuth2 refresh
        let bearer_token = self.generate_bearer_auth_token(ctx).await?;

        // Then exchange for impersonated access token
        let access_token = self.generate_access_token(ctx, &bearer_token).await?;

        Ok(Some(Credential::with_token(access_token)))
    }
}
