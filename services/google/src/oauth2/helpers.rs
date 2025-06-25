//! OAuth2 helper functions for Google services

use http::{header::CONTENT_TYPE, Method, StatusCode};
use log::error;
use serde::{de::DeserializeOwned, Serialize};

use reqsign_core::{time::{now, DateTime}, Context, Error, Result};

use crate::credential::Token;

/// Send an OAuth2 POST request and parse the response.
///
/// This function handles the common pattern of:
/// 1. Serializing the request body
/// 2. Building an HTTP POST request
/// 3. Sending the request via the context
/// 4. Checking the response status
/// 5. Parsing the JSON response
///
/// # Arguments
/// * `ctx` - The context for HTTP operations
/// * `url` - The OAuth2 endpoint URL
/// * `body` - The request body to serialize
/// * `content_type` - The content type ("application/json" or "application/x-www-form-urlencoded")
pub async fn oauth2_post<T: Serialize, R: DeserializeOwned>(
    ctx: &Context,
    url: &str,
    body: &T,
    content_type: &str,
) -> Result<R> {
    oauth2_post_with_auth(ctx, url, body, content_type, None).await
}

/// Send an OAuth2 POST request with optional authorization header and parse the response.
///
/// Similar to `oauth2_post` but allows setting an authorization header.
///
/// # Arguments
/// * `ctx` - The context for HTTP operations
/// * `url` - The OAuth2 endpoint URL
/// * `body` - The request body to serialize
/// * `content_type` - The content type ("application/json" or "application/x-www-form-urlencoded")
/// * `auth_header` - Optional authorization header value (e.g., "Bearer token")
pub async fn oauth2_post_with_auth<T: Serialize, R: DeserializeOwned>(
    ctx: &Context,
    url: &str,
    body: &T,
    content_type: &str,
    auth_header: Option<&str>,
) -> Result<R> {
    // Serialize the request body based on content type
    let body_bytes = match content_type {
        "application/json" => serde_json::to_vec(body)
            .map_err(|e| Error::unexpected("failed to serialize request").with_source(e))?,
        "application/x-www-form-urlencoded" => {
            // For now, we'll just use JSON serialization for form data
            // In the future, we could add proper form encoding
            serde_json::to_vec(body)
                .map_err(|e| Error::unexpected("failed to serialize request").with_source(e))?
        }
        _ => return Err(Error::unexpected("unsupported content type")),
    };

    // Build the HTTP request
    let mut builder = http::Request::builder()
        .method(Method::POST)
        .uri(url)
        .header(CONTENT_TYPE, content_type);
    
    if let Some(auth) = auth_header {
        builder = builder.header("Authorization", auth);
    }
    
    let req = builder
        .body(body_bytes.into())
        .map_err(|e| Error::unexpected("failed to build HTTP request").with_source(e))?;

    // Send the request
    let resp = ctx.http_send(req).await?;

    // Check response status
    if resp.status() != StatusCode::OK {
        error!("OAuth2 request to {} failed: {:?}", url, resp);
        let body = String::from_utf8_lossy(resp.body());
        return Err(Error::unexpected(format!(
            "OAuth2 request failed ({}): {}",
            resp.status(),
            body
        )));
    }

    // Parse the response
    serde_json::from_slice(resp.body())
        .map_err(|e| Error::unexpected("failed to parse OAuth2 response").with_source(e))
}

/// Send an OAuth2 GET request and parse the response.
///
/// Similar to `oauth2_post` but for GET requests with authorization header.
pub async fn oauth2_get<R: DeserializeOwned>(
    ctx: &Context,
    url: &str,
    auth_header: Option<(&str, &str)>,
) -> Result<R> {
    let mut builder = http::Request::builder().method(Method::GET).uri(url);

    if let Some((name, value)) = auth_header {
        builder = builder.header(name, value);
    }

    let req = builder
        .body(Vec::<u8>::new().into())
        .map_err(|e| Error::unexpected("failed to build HTTP request").with_source(e))?;

    let resp = ctx.http_send(req).await?;

    if resp.status() != StatusCode::OK {
        error!("OAuth2 GET request to {} failed: {:?}", url, resp);
        let body = String::from_utf8_lossy(resp.body());
        return Err(Error::unexpected(format!(
            "OAuth2 request failed ({}): {}",
            resp.status(),
            body
        )));
    }

    serde_json::from_slice(resp.body())
        .map_err(|e| Error::unexpected("failed to parse OAuth2 response").with_source(e))
}

/// Convert a standard OAuth2 token response to our Token type.
pub fn token_from_response(resp: &super::types::TokenResponse) -> Token {
    Token {
        access_token: resp.access_token.clone(),
        expires_at: resp.expires_in.map(|expires_in| {
            now() + chrono::TimeDelta::try_seconds(expires_in as i64).expect("in bounds")
        }),
    }
}

/// Convert a standard OAuth2 token response to our Token type with a required expiration.
/// This is used when we know the token always has an expiration (e.g., VM metadata service).
pub fn token_from_response_required_expiry(resp: &super::types::TokenResponse) -> Result<Token> {
    let expires_in = resp.expires_in.ok_or_else(|| {
        Error::unexpected("token response missing required expires_in field")
    })?;
    
    Ok(Token {
        access_token: resp.access_token.clone(),
        expires_at: Some(
            now() + chrono::TimeDelta::try_seconds(expires_in as i64).expect("in bounds")
        ),
    })
}

/// Parse an RFC3339 timestamp string to a DateTime.
pub fn parse_rfc3339_expiration(expire_time: &str) -> Result<Option<DateTime>> {
    chrono::DateTime::parse_from_rfc3339(expire_time)
        .map(|dt| Some(dt.with_timezone(&chrono::Utc)))
        .map_err(|e| Error::unexpected("failed to parse expire time").with_source(e))
}