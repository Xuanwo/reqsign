use crate::azure::storage::config::Config;

use http::HeaderValue;
use http::Method;
use http::Request;
use reqwest::Client;
use serde::Deserialize;
use std::str;

pub async fn get_client_secret_token(config: &Config) -> anyhow::Result<Option<LoginResponse>> {
    let (secret, tenant_id, client_id, authority_host) = match (
        &config.client_secret,
        &config.tenant_id,
        &config.client_id,
        &config.authority_host,
    ) {
        (Some(client_secret), Some(tenant_id), Some(client_id), Some(authority_host)) => {
            (client_secret, tenant_id, client_id, authority_host)
        }
        _ => return Ok(None),
    };
    let url = &format!("{authority_host}/{tenant_id}/oauth2/v2.0/token");
    let scopes: &[&str] = &[STORAGE_TOKEN_SCOPE];
    let encoded_body: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("scope", &scopes.join(" "))
        .append_pair("client_secret", secret)
        .append_pair("grant_type", "client_credentials")
        .finish();

    let mut req = Request::builder()
        .method(Method::POST)
        .uri(url.to_string())
        .body(encoded_body)?;
    req.headers_mut().insert(
        http::header::CONTENT_TYPE.as_str(),
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );

    req.headers_mut()
        .insert(API_VERSION, HeaderValue::from_static("2019-06-01"));

    let res = Client::new().execute(req.try_into()?).await?;
    let rsp_status = res.status();
    let rsp_body = res.text().await?;

    if !rsp_status.is_success() {
        return Err(anyhow::anyhow!(
            "Failed to get token from client_credentials, rsp_status = {}, rsp_body = {}",
            rsp_status,
            rsp_body
        ));
    }

    let resp: LoginResponse = serde_json::from_str(&rsp_body)?;
    Ok(Some(resp))
}

pub const API_VERSION: &str = "api-version";
const STORAGE_TOKEN_SCOPE: &str = "https://storage.azure.com/.default";
/// Gets an access token for the specified resource and configuration.
///
/// See <https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=portal,http#using-the-rest-protocol>

#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
    pub expires_in: i64,
    pub access_token: String,
}

impl From<LoginResponse> for super::credential::Credential {
    fn from(response: LoginResponse) -> Self {
        super::credential::Credential::BearerToken(
            response.access_token,
            chrono::Utc::now()
                + chrono::TimeDelta::seconds(
                    response.expires_in.saturating_sub(10).clamp(0, i64::MAX),
                ),
        )
    }
}
