use std::{fs, str};

use http::HeaderValue;
use http::Method;
use http::Request;
use reqwest::Client;
use reqwest::Url;
use serde::Deserialize;

use super::config::Config;

pub const API_VERSION: &str = "api-version";
const STORAGE_TOKEN_SCOPE: &str = "https://storage.azure.com/.default";
/// Gets an access token for the specified resource and configuration.
///
/// See <https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=portal,http#using-the-rest-protocol>
pub async fn get_workload_identity_token(config: &Config) -> anyhow::Result<Option<LoginResponse>> {
    let (token_file, tenant_id, client_id, authority_host) = match (
        &config.federated_token_file,
        &config.tenant_id,
        &config.client_id,
        &config.authority_host,
    ) {
        (Some(token_file), Some(tenant_id), Some(client_id), Some(authority_host)) => {
            (token_file, tenant_id, client_id, authority_host)
        }
        _ => return Ok(None),
    };

    let token = fs::read_to_string(token_file)?;
    let url = Url::parse(authority_host)?.join(&format!("/{tenant_id}/oauth2/v2.0/token"))?;
    let scopes: &[&str] = &[STORAGE_TOKEN_SCOPE];
    let encoded_body: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("scope", &scopes.join(" "))
        .append_pair(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )
        .append_pair("client_assertion", &token)
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
            "Failed to get token from workload identity credential, rsp_status = {}, rsp_body = {}",
            rsp_status,
            rsp_body
        ));
    }

    let resp: LoginResponse = serde_json::from_str(&rsp_body)?;
    Ok(Some(resp))
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
    pub expires_on: Option<String>,
    pub access_token: String,
}
