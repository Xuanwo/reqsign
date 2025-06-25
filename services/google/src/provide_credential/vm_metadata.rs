use log::debug;

use reqsign_core::{Context, ProvideCredential, Result};

use crate::credential::Credential;
use crate::oauth2::{helpers, types::TokenResponse};


/// VmMetadataCredentialProvider loads tokens from Google Compute Engine VM metadata service.
#[derive(Debug, Clone, Default)]
pub struct VmMetadataCredentialProvider {
    scope: Option<String>,
}

impl VmMetadataCredentialProvider {
    /// Create a new VmMetadataCredentialProvider.
    pub fn new() -> Self {
        Self { scope: None }
    }

    /// Set the OAuth2 scope.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }
}

#[async_trait::async_trait]
impl ProvideCredential for VmMetadataCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Get scope from instance, environment, or use default
        let scope = self
            .scope
            .clone()
            .or_else(|| ctx.env_var(crate::constants::GOOGLE_SCOPE))
            .unwrap_or_else(|| crate::constants::DEFAULT_SCOPE.to_string());

        // Use "default" service account if not specified
        let service_account = "default";

        debug!(
            "loading token from VM metadata service for account: {}",
            service_account
        );

        let url = format!(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/{}/token?scopes={}",
            service_account, scope
        );

        // Use the new OAuth2 helper function
        let token_resp: TokenResponse = match helpers::oauth2_get(
            ctx,
            &url,
            Some(("Metadata-Flavor", "Google")),
        )
        .await
        {
            Ok(resp) => resp,
            Err(_) => {
                // VM metadata service might not be available (e.g., not running on GCE)
                debug!("VM metadata service not available or returned error");
                return Ok(None);
            }
        };

        // Convert response to Token (VM metadata always includes expires_in)
        let token = helpers::token_from_response_required_expiry(&token_resp)?;

        Ok(Some(Credential::with_token(token)))
    }
}
