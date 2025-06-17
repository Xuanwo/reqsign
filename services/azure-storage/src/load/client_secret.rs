use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential};

/// Load credential from Azure Client Secret.
///
/// This loader implements the Azure Client Secret authentication flow,
/// which allows applications to authenticate to Azure services using
/// a client ID and client secret.
///
/// Reference: <https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow>
#[derive(Debug, Default)]
pub struct ClientSecretLoader {
    tenant_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    authority_host: Option<String>,
}

impl ClientSecretLoader {
    /// Create a new client secret loader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the Azure tenant ID.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Set the Azure client ID.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the Azure client secret.
    pub fn with_client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Set the authority host URL.
    pub fn with_authority_host(mut self, authority_host: impl Into<String>) -> Self {
        self.authority_host = Some(authority_host.into());
        self
    }
}

#[async_trait]
impl ProvideCredential for ClientSecretLoader {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        // Check if all required parameters are available
        let tenant_id = match &self.tenant_id {
            Some(id) if !id.is_empty() => id,
            _ => return Ok(None),
        };

        let client_id = match &self.client_id {
            Some(id) if !id.is_empty() => id,
            _ => return Ok(None),
        };

        let client_secret = match &self.client_secret {
            Some(secret) if !secret.is_empty() => secret,
            _ => return Ok(None),
        };

        let authority_host = self
            .authority_host
            .as_deref()
            .unwrap_or("https://login.microsoftonline.com");

        let token =
            get_client_secret_token(tenant_id, client_id, client_secret, authority_host, ctx)
                .await?;

        match token {
            Some(token_response) => {
                let expires_on = reqsign_core::time::now()
                    + chrono::TimeDelta::try_seconds(token_response.expires_in as i64)
                        .unwrap_or_else(|| chrono::TimeDelta::try_minutes(10).expect("in bounds"));

                Ok(Some(Credential::with_bearer_token(
                    token_response.access_token,
                    Some(expires_on),
                )))
            }
            None => Ok(None),
        }
    }
}

#[derive(serde::Deserialize)]
struct ClientSecretTokenResponse {
    access_token: String,
    expires_in: u64,
}

async fn get_client_secret_token(
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
    authority_host: &str,
    ctx: &Context,
) -> anyhow::Result<Option<ClientSecretTokenResponse>> {
    let url = format!(
        "{}/{}/oauth2/v2.0/token",
        authority_host.trim_end_matches('/'),
        tenant_id
    );

    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("scope", "https://storage.azure.com/.default")
        .append_pair("client_id", client_id)
        .append_pair("client_secret", client_secret)
        .append_pair("grant_type", "client_credentials")
        .finish();

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(bytes::Bytes::from(body))?;

    let resp = ctx.http_send(req).await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = String::from_utf8_lossy(resp.body());
        return Err(anyhow::anyhow!(
            "Client secret request failed with status {}: {}",
            status,
            body
        ));
    }

    let token: ClientSecretTokenResponse = serde_json::from_slice(resp.body())?;
    Ok(Some(token))
}
