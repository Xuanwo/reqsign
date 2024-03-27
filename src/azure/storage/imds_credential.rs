use std::str;

use http::HeaderValue;
use http::Method;
use http::Request;
use reqwest::Client;
use reqwest::Url;
use serde::Deserialize;

use super::config::Config;

const MSI_API_VERSION: &str = "2019-08-01";
const MSI_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";

/// Gets an access token for the specified resource and configuration.
///
/// See <https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=portal,http#using-the-rest-protocol>
pub async fn get_access_token(resource: &str, config: &Config) -> anyhow::Result<AccessToken> {
    let endpoint = config.endpoint.as_deref().unwrap_or(MSI_ENDPOINT);
    let mut query_items = vec![("api-version", MSI_API_VERSION), ("resource", resource)];

    match (
        config.object_id.as_ref(),
        config.client_id.as_ref(),
        config.msi_res_id.as_ref(),
    ) {
        (Some(object_id), None, None) => query_items.push(("object_id", object_id)),
        (None, Some(client_id), None) => query_items.push(("client_id", client_id)),
        (None, None, Some(msi_res_id)) => query_items.push(("msi_res_id", msi_res_id)),
        // Only one of the object_id, client_id, or msi_res_id can be specified, if you specify both, will ignore all.
        _ => (),
    };

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

    if !rsp_status.is_success() {
        return Err(anyhow::anyhow!("Failed to get token from IMDS endpoint"));
    }

    let token: AccessToken = serde_json::from_str(&rsp_body)?;

    Ok(token)
}

// NOTE: expires_on is a String version of unix epoch time, not an integer.
// https://docs.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=dotnet#rest-protocol-examples
#[derive(Debug, Clone, Deserialize)]
#[allow(unused)]
pub struct AccessToken {
    pub access_token: String,
    pub expires_on: String,
    pub token_type: String,
    pub resource: String,
}
