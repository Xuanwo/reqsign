use anyhow::Result;
use log::debug;
use serde::Deserialize;

use reqsign_core::{time::now, Context, Load};

use crate::config::Config;
use crate::key::Token;

/// VM metadata token response.
#[derive(Deserialize)]
struct VmMetadataTokenResponse {
    access_token: String,
    expires_in: u64,
}

/// VmMetadataLoader loads tokens from Google Compute Engine VM metadata service.
#[derive(Debug, Clone)]
pub struct VmMetadataLoader {
    config: Config,
}

impl VmMetadataLoader {
    /// Create a new VmMetadataLoader.
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl Load for VmMetadataLoader {
    type Key = Token;

    async fn load(&self, ctx: &Context) -> Result<Option<Self::Key>> {
        let scope = self
            .config
            .scope
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("scope is required for VM metadata"))?;

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
            .body(Vec::<u8>::new().into())?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            // VM metadata service might not be available (e.g., not running on GCE)
            debug!("VM metadata service not available or returned error");
            return Ok(None);
        }

        let token_resp: VmMetadataTokenResponse = serde_json::from_slice(resp.body())?;

        let expires_at = now()
            + chrono::TimeDelta::try_seconds(token_resp.expires_in as i64).expect("in bounds");

        Ok(Some(Token {
            access_token: token_resp.access_token,
            expires_at: Some(expires_at),
        }))
    }
}
