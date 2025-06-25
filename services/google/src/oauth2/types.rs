//! OAuth2 type definitions for Google services

use serde::Deserialize;

/// Common OAuth2 token response structure used by multiple OAuth2 endpoints.
///
/// This structure is used by:
/// - Token refresh endpoints (for authorized users and service accounts)
/// - STS token exchange endpoints
/// - VM metadata service
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct TokenResponse {
    /// The access token issued by the authorization server.
    pub access_token: String,
    
    /// The lifetime in seconds of the access token.
    #[serde(default)]
    pub expires_in: Option<u64>,
    
    /// The type of token issued (typically "Bearer").
    #[serde(default)]
    pub token_type: Option<String>,
}

/// Response from service account impersonation endpoints.
///
/// This structure is used when impersonating a service account to get an access token.
/// The field names are different from the standard OAuth2 response (camelCase instead of snake_case).
#[derive(Debug, Clone, Deserialize)]
pub struct ImpersonatedTokenResponse {
    /// The access token that can be used to authenticate as the impersonated service account.
    #[serde(rename = "accessToken")]
    pub access_token: String,
    
    /// The time at which the access token expires (RFC3339 format).
    #[serde(rename = "expireTime")]
    pub expire_time: String,
}