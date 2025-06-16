use reqsign_core::{time::now, time::DateTime, Key as KeyTrait};
use reqsign_core::hash::base64_decode;
use std::fmt::{self, Debug};
use anyhow::anyhow;

/// ServiceAccount holds the client email and private key for service account authentication.
#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServiceAccount {
    /// Private key of credential
    pub private_key: String,
    /// The client email of credential
    pub client_email: String,
}

impl Debug for ServiceAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("client_email", &self.client_email)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// ImpersonatedServiceAccount holds the source credentials for impersonation.
#[derive(Clone, serde::Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct ImpersonatedServiceAccount {
    /// The URL to obtain the access token for the impersonated service account.
    pub service_account_impersonation_url: String,
    /// The underlying source credential.
    pub source_credentials: SourceCredentials,
    /// Optional delegates for the impersonation.
    #[serde(default)]
    pub delegates: Vec<String>,
}

/// SourceCredentials holds the OAuth2 credentials.
#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SourceCredentials {
    /// The client ID.
    pub client_id: String,
    /// The client secret.
    pub client_secret: String,
    /// The refresh token.
    pub refresh_token: String,
}

impl Debug for SourceCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

/// ExternalAccount holds the configuration for external account authentication.
#[derive(Clone, serde::Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct ExternalAccount {
    /// The audience for the external account.
    pub audience: String,
    /// The subject token type.
    pub subject_token_type: String,
    /// The token URL to exchange tokens.
    pub token_url: String,
    /// The credential source.
    pub credential_source: CredentialSource,
    /// Optional service account impersonation URL.
    pub service_account_impersonation_url: Option<String>,
    /// Optional service account impersonation options.
    pub service_account_impersonation: Option<ServiceAccountImpersonation>,
}

/// Service account impersonation options.
#[derive(Clone, serde::Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct ServiceAccountImpersonation {
    /// The lifetime in seconds to be used when exchanging the STS token.
    pub token_lifetime_seconds: Option<usize>,
}

/// CredentialSource defines where to obtain the external account credentials.
#[derive(Clone, serde::Deserialize, Debug)]
#[serde(untagged)]
pub enum CredentialSource {
    /// URL-based credential source.
    #[serde(rename_all = "snake_case")]
    UrlSourced(UrlSourcedCredential),
    /// File-based credential source.
    #[serde(rename_all = "snake_case")]
    FileSourced(FileSourcedCredential),
}

/// URL-based credential source configuration.
#[derive(Clone, serde::Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct UrlSourcedCredential {
    /// The URL to fetch credentials from.
    pub url: String,
    /// The format of the response.
    pub format: FormatType,
    /// Optional headers to include in the request.
    pub headers: Option<std::collections::HashMap<String, String>>,
}

/// File-based credential source configuration.
#[derive(Clone, serde::Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct FileSourcedCredential {
    /// The file path to read credentials from.
    pub file: String,
    /// The format of the file.
    pub format: FormatType,
}

/// Format type for credential sources.
#[derive(Clone, serde::Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FormatType {
    /// JSON format.
    Json {
        /// The JSON path to extract the subject token.
        subject_token_field_name: String,
    },
    /// Text format.
    Text,
}

impl FormatType {
    /// Parse a slice of bytes as the expected format.
    pub fn parse(&self, slice: &[u8]) -> anyhow::Result<String> {
        match &self {
            Self::Text => Ok(String::from_utf8(slice.to_vec())?),
            Self::Json {
                subject_token_field_name,
            } => {
                let value: serde_json::Value = serde_json::from_slice(slice)?;
                match value.get(subject_token_field_name) {
                    Some(serde_json::Value::String(access_token)) => Ok(access_token.clone()),
                    _ => anyhow::bail!("JSON missing token field {subject_token_field_name}"),
                }
            }
        }
    }
}

/// Token represents an OAuth2 access token with expiration.
#[derive(Clone, Default)]
pub struct Token {
    /// The access token.
    pub access_token: String,
    /// The expiration time of the token.
    pub expires_at: Option<DateTime>,
}

impl Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("access_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl KeyTrait for Token {
    fn is_valid(&self) -> bool {
        if self.access_token.is_empty() {
            return false;
        }

        match self.expires_at {
            Some(expires_at) => {
                // Consider token invalid if it expires within 2 minutes
                let buffer = chrono::TimeDelta::try_seconds(2 * 60).expect("in bounds");
                now() < expires_at - buffer
            }
            None => true, // No expiration means always valid
        }
    }
}

/// Credential represents different types of Google credentials.
#[derive(Clone, Debug)]
pub enum Credential {
    /// Service account with private key.
    ServiceAccount(ServiceAccount),
    /// OAuth2 access token.
    Token(Token),
}

impl KeyTrait for Credential {
    fn is_valid(&self) -> bool {
        match self {
            Credential::ServiceAccount(_) => true, // Service accounts don't expire
            Credential::Token(token) => token.is_valid(),
        }
    }
}

/// CredentialType indicates the type of credential in a file.
#[derive(Clone, serde::Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum CredentialType {
    /// Impersonated service account.
    ImpersonatedServiceAccount,
    /// External account.
    ExternalAccount,
    /// Service account.
    ServiceAccount,
}

/// RawCredential represents the raw credential file that can be one of multiple types.
#[derive(Clone, Debug)]
pub struct RawCredential {
    /// Service account, if present.
    pub service_account: Option<ServiceAccount>,
    /// Impersonated service account, if present.
    pub impersonated_service_account: Option<ImpersonatedServiceAccount>,
    /// External account, if present.
    pub external_account: Option<ExternalAccount>,
}

impl RawCredential {
    /// Parse raw credential from bytes.
    pub fn from_slice(v: &[u8]) -> anyhow::Result<Self> {
        let service_account = serde_json::from_slice(v).ok();
        let impersonated_service_account = serde_json::from_slice(v).ok();
        let external_account = serde_json::from_slice(v).ok();

        let cred = RawCredential {
            service_account,
            impersonated_service_account,
            external_account,
        };

        if cred.service_account.is_none()
            && cred.impersonated_service_account.is_none()
            && cred.external_account.is_none()
        {
            return Err(anyhow!("Couldn't deserialize credential file"));
        }

        Ok(cred)
    }

    /// Parse raw credential from base64-encoded content.
    pub fn from_base64(content: &str) -> anyhow::Result<Self> {
        let decoded = base64_decode(content)?;
        Self::from_slice(&decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_type_parse_text() {
        let format = FormatType::Text;
        let data = b"test-token";
        let result = format.parse(data).unwrap();
        assert_eq!("test-token", result);
    }

    #[test]
    fn test_format_type_parse_json() {
        let format = FormatType::Json {
            subject_token_field_name: "access_token".to_string(),
        };
        let data = br#"{"access_token": "test-token", "expires_in": 3600}"#;
        let result = format.parse(data).unwrap();
        assert_eq!("test-token", result);
    }

    #[test]
    fn test_format_type_parse_json_missing_field() {
        let format = FormatType::Json {
            subject_token_field_name: "access_token".to_string(),
        };
        let data = br#"{"wrong_field": "test-token"}"#;
        let result = format.parse(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_is_valid() {
        let mut token = Token {
            access_token: "test".to_string(),
            expires_at: None,
        };
        assert!(token.is_valid());

        // Token with future expiration
        token.expires_at = Some(now() + chrono::TimeDelta::try_hours(1).unwrap());
        assert!(token.is_valid());

        // Token that expires within 2 minutes
        token.expires_at = Some(now() + chrono::TimeDelta::try_seconds(30).unwrap());
        assert!(!token.is_valid());

        // Expired token
        token.expires_at = Some(now() - chrono::TimeDelta::try_hours(1).unwrap());
        assert!(!token.is_valid());

        // Empty access token
        token.access_token = String::new();
        assert!(!token.is_valid());
    }

    #[test]
    fn test_credential_is_valid() {
        // Service account is always valid
        let cred = Credential::ServiceAccount(ServiceAccount {
            client_email: "test@example.com".to_string(),
            private_key: "key".to_string(),
        });
        assert!(cred.is_valid());

        // Valid token
        let cred = Credential::Token(Token {
            access_token: "test".to_string(),
            expires_at: Some(now() + chrono::TimeDelta::try_hours(1).unwrap()),
        });
        assert!(cred.is_valid());

        // Invalid token
        let cred = Credential::Token(Token {
            access_token: String::new(),
            expires_at: None,
        });
        assert!(!cred.is_valid());
    }
}