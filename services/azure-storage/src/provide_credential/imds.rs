use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, Result};

/// Load credential from Azure Instance Metadata Service (IMDS).
///
/// This loader attempts to retrieve an access token from the Azure Instance Metadata Service
/// which is available on Azure VMs and other Azure compute resources.
///
/// Reference: <https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=portal,http#using-the-rest-protocol>
#[derive(Debug, Default)]
pub struct ImdsCredentialProvider {
    object_id: Option<String>,
    client_id: Option<String>,
    msi_res_id: Option<String>,
    msi_secret: Option<String>,
    endpoint: Option<String>,
}

impl ImdsCredentialProvider {
    /// Create a new IMDS loader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set object ID for user-assigned managed identity.
    pub fn with_object_id(mut self, object_id: impl Into<String>) -> Self {
        self.object_id = Some(object_id.into());
        self
    }

    /// Set client ID for user-assigned managed identity.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set MSI resource ID for user-assigned managed identity.
    pub fn with_msi_res_id(mut self, msi_res_id: impl Into<String>) -> Self {
        self.msi_res_id = Some(msi_res_id.into());
        self
    }

    /// Set MSI secret header value.
    pub fn with_msi_secret(mut self, msi_secret: impl Into<String>) -> Self {
        self.msi_secret = Some(msi_secret.into());
        self
    }

    /// Set custom IMDS endpoint.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }
}

#[async_trait]
impl ProvideCredential for ImdsCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let token = get_access_token("https://storage.azure.com/", self, ctx).await?;

        let expires_on = if token.expires_on.is_empty() {
            reqsign_core::time::now() + chrono::TimeDelta::try_minutes(10).expect("in bounds")
        } else {
            reqsign_core::time::parse_rfc3339(&token.expires_on).map_err(|e| {
                reqsign_core::Error::unexpected("failed to parse expires_on time").with_source(e)
            })?
        };

        Ok(Some(Credential::with_bearer_token(
            token.access_token,
            Some(expires_on),
        )))
    }
}

#[derive(serde::Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    expires_on: String,
}

async fn get_access_token(
    resource: &str,
    loader: &ImdsCredentialProvider,
    ctx: &Context,
) -> Result<AccessTokenResponse> {
    let endpoint = loader
        .endpoint
        .as_deref()
        .unwrap_or("http://169.254.169.254/metadata/identity/oauth2/token");

    let mut url = format!("{}?api-version=2018-02-01&resource={}", endpoint, resource);

    // Add identity parameters if specified
    if let Some(object_id) = &loader.object_id {
        url.push_str(&format!("&object_id={}", object_id));
    } else if let Some(client_id) = &loader.client_id {
        url.push_str(&format!("&client_id={}", client_id));
    } else if let Some(msi_res_id) = &loader.msi_res_id {
        url.push_str(&format!("&msi_res_id={}", msi_res_id));
    }

    let mut req = http::Request::builder()
        .method(http::Method::GET)
        .uri(&url)
        .header("Metadata", "true");

    // Add MSI secret header if provided
    if let Some(msi_secret) = &loader.msi_secret {
        req = req.header("X-IDENTITY-HEADER", msi_secret);
    }

    let req = req.body(bytes::Bytes::new()).map_err(|e| {
        reqsign_core::Error::unexpected("failed to build IMDS request").with_source(e)
    })?;

    let resp = ctx.http_send(req).await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = String::from_utf8_lossy(resp.body());
        return Err(reqsign_core::Error::unexpected(format!(
            "IMDS request failed with status {}: {}",
            status, body
        )));
    }

    let token: AccessTokenResponse = serde_json::from_slice(resp.body()).map_err(|e| {
        reqsign_core::Error::unexpected("failed to parse IMDS response").with_source(e)
    })?;
    Ok(token)
}
