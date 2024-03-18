use std::str;

use http::HeaderValue;
use http::Method;
use http::Request;
use reqwest::Client;
use reqwest::Url;
use serde::Deserialize;
use std::fs;

use super::config::Config;

const MSI_API_VERSION: &str = "2019-08-01";
const MSI_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";

/// Gets an access token for the specified resource and configuration.
///
/// See <https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=portal,http#using-the-rest-protocol>
pub async fn get_workload_identity_token(
    resource: &str,
    config: &Config,
) -> anyhow::Result<Option<AccessToken>> {
    let token = match (
        &config.azure_federated_token,
        &config.azure_federated_token_file,
    ) {
        (Some(token), Some(_)) | (Some(token), None) => token.clone(),
        (None, Some(token_file)) => {
            let token = fs::read_to_string(token_file)?;
            token
        }
        _ => return Ok(None),
    };
    let tenant_id = if let Some(tenant_id) = &config.azure_tenant_id_env_key {
        tenant_id
    } else {
        return Ok(None);
    };
    let client_id = if let Some(client_id) = &config.client_id {
        client_id
    } else {
        return Ok(None);
    };

    let endpoint = config.endpoint.as_deref().unwrap_or(MSI_ENDPOINT);

    let mut query_items = vec![("api-version", MSI_API_VERSION), ("resource", resource)];
    query_items.push(("token", &token));
    query_items.push(("tenant_id", &tenant_id));
    query_items.push(("client_id", &client_id));

    let url = Url::parse_with_params(endpoint, &query_items)?;
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(url.to_string())
        .body("")?;

    req.headers_mut()
        .insert("metadata", HeaderValue::from_static("true"));

    if let Some(secret) = &config.msi_secret {
        req.headers_mut()
            .insert("x-identity-header", HeaderValue::from_str(secret)?);
    };

    let res = Client::new().execute(req.try_into()?).await?;
    let rsp_status = res.status();
    let rsp_body = res.text().await?;
;

    if !rsp_status.is_success() {
        return Err(anyhow::anyhow!("Failed to get token from working identity credential"));
    }

    let token: AccessToken = serde_json::from_str(&rsp_body)?;
    Ok(Some(token))
}

#[derive(Debug, Clone, Deserialize)]
#[allow(unused)]
pub struct AccessToken {
    pub access_token: String,
    pub expires_on: String,

}
