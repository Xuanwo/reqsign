use log::debug;
use serde::Deserialize;

use reqsign_core::{time::now, Context, ProvideCredential, Result};

use crate::config::Config;
use crate::credential::{Credential, Token};

/// VM metadata token response.
#[derive(Deserialize)]
struct VmMetadataTokenResponse {
    access_token: String,
    expires_in: u64,
}

/// VmMetadataCredentialProvider loads tokens from Google Compute Engine VM metadata service.
#[derive(Debug, Clone)]
pub struct VmMetadataCredentialProvider {
    config: Config,
}

impl VmMetadataCredentialProvider {
    /// Create a new VmMetadataCredentialProvider.
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl ProvideCredential for VmMetadataCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let scope = self
            .config
            .scope
            .as_ref()
            .ok_or_else(|| reqsign_core::Error::config_invalid("scope is required for VM metadata"))?;

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

        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(&url)
            .header("Metadata-Flavor", "Google")
            .body(Vec::<u8>::new().into()).map_err(|e| reqsign_core::Error::unexpected("failed to build HTTP request").with_source(e))?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            // VM metadata service might not be available (e.g., not running on GCE)
            debug!("VM metadata service not available or returned error");
            return Ok(None);
        }

        let token_resp: VmMetadataTokenResponse = serde_json::from_slice(resp.body()).map_err(|e| reqsign_core::Error::unexpected("failed to parse VM metadata response").with_source(e))?;

        let expires_at = now()
            + chrono::TimeDelta::try_seconds(token_resp.expires_in as i64).expect("in bounds");

        let token = Token {
            access_token: token_resp.access_token,
            expires_at: Some(expires_at),
        };

        Ok(Some(Credential::with_token(token)))
    }
}
