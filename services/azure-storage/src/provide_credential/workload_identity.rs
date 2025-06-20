use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential};

/// Load credential from Azure Workload Identity.
///
/// This loader implements the Azure Workload Identity authentication flow,
/// which allows workloads running in Kubernetes to authenticate to Azure services
/// using a federated token.
///
/// Reference: <https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview>
#[derive(Debug, Default)]
pub struct WorkloadIdentityCredentialProvider {
    tenant_id: Option<String>,
    client_id: Option<String>,
    federated_token_file: Option<String>,
    authority_host: Option<String>,
}

impl WorkloadIdentityCredentialProvider {
    /// Create a new workload identity loader.
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

    /// Set the federated token file path.
    pub fn with_federated_token_file(mut self, federated_token_file: impl Into<String>) -> Self {
        self.federated_token_file = Some(federated_token_file.into());
        self
    }

    /// Set the authority host URL.
    pub fn with_authority_host(mut self, authority_host: impl Into<String>) -> Self {
        self.authority_host = Some(authority_host.into());
        self
    }
}

#[async_trait]
impl ProvideCredential for WorkloadIdentityCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Self::Credential>> {
        // Check if all required parameters are available
        let tenant_id = match &self.tenant_id {
            Some(id) if !id.is_empty() => id,
            _ => return Ok(None),
        };

        let client_id = match &self.client_id {
            Some(id) if !id.is_empty() => id,
            _ => return Ok(None),
        };

        let federated_token_file = match &self.federated_token_file {
            Some(file) if !file.is_empty() => file,
            _ => return Ok(None),
        };

        let authority_host = self
            .authority_host
            .as_deref()
            .unwrap_or("https://login.microsoftonline.com");

        let token = get_workload_identity_token(
            tenant_id,
            client_id,
            federated_token_file,
            authority_host,
            ctx,
        )
        .await?;

        match token {
            Some(token_response) => {
                let expires_on = match token_response.expires_on {
                    Some(expires_on) => reqsign_core::time::parse_rfc3339(&expires_on)
                        .map_err(|e| reqsign_core::Error::unexpected("failed to parse expires_on time").with_source(e))?,
                    None => {
                        reqsign_core::time::now()
                            + chrono::TimeDelta::try_minutes(10).expect("in bounds")
                    }
                };

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
struct WorkloadIdentityTokenResponse {
    access_token: String,
    expires_on: Option<String>,
}

async fn get_workload_identity_token(
    tenant_id: &str,
    client_id: &str,
    federated_token_file: &str,
    authority_host: &str,
    ctx: &Context,
) -> reqsign_core::Result<Option<WorkloadIdentityTokenResponse>> {
    // Read the federated token from file
    let federated_token = match ctx.file_read(federated_token_file).await {
        Ok(content) => String::from_utf8(content)
            .map_err(|e| reqsign_core::Error::unexpected("failed to parse federated token file as UTF-8").with_source(e))?,
        Err(_) => return Ok(None), // File doesn't exist or can't be read
    };

    if federated_token.trim().is_empty() {
        return Ok(None);
    }

    let url = format!(
        "{}/{}/oauth2/v2.0/token",
        authority_host.trim_end_matches('/'),
        tenant_id
    );

    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("scope", "https://storage.azure.com/.default")
        .append_pair("client_id", client_id)
        .append_pair(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )
        .append_pair("client_assertion", federated_token.trim())
        .append_pair("grant_type", "client_credentials")
        .finish();

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(bytes::Bytes::from(body))
        .map_err(|e| reqsign_core::Error::unexpected("failed to build workload identity request").with_source(e))?;

    let resp = ctx.http_send(req).await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = String::from_utf8_lossy(resp.body());
        return Err(reqsign_core::Error::unexpected(
            format!("Workload identity request failed with status {}: {}", status, body)
        ));
    }

    let token: WorkloadIdentityTokenResponse = serde_json::from_slice(resp.body())
        .map_err(|e| reqsign_core::Error::unexpected("failed to parse workload identity response").with_source(e))?;
    Ok(Some(token))
}
