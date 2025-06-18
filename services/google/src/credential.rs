use anyhow::anyhow;
use reqsign_core::hash::base64_decode;
use reqsign_core::{time::now, time::DateTime, utils::Redact, SigningCredential as KeyTrait};
use std::fmt::{self, Debug};

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
            .field("private_key", &Redact::from(&self.private_key))
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
            .field("client_secret", &Redact::from(&self.client_secret))
            .field("refresh_token", &Redact::from(&self.refresh_token))
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
            .field("access_token", &Redact::from(&self.access_token))
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

/// Credential represents Google credentials that may contain both service account and token.
///
/// This unified credential type allows for flexible authentication strategies:
/// - Service account only: Used for signed URL generation
/// - Token only: Used for Bearer authentication  
/// - Both: Allows automatic token refresh when token expires
#[derive(Clone, Debug, Default)]
pub struct Credential {
    /// Service account information, if available.
    pub service_account: Option<ServiceAccount>,
    /// OAuth2 access token, if available.
    pub token: Option<Token>,
}

impl Credential {
    /// Create a credential with only a service account.
    pub fn with_service_account(service_account: ServiceAccount) -> Self {
        Self {
            service_account: Some(service_account),
            token: None,
        }
    }

    /// Create a credential with only a token.
    pub fn with_token(token: Token) -> Self {
        Self {
            service_account: None,
            token: Some(token),
        }
    }

    /// Check if the credential has a service account.
    pub fn has_service_account(&self) -> bool {
        self.service_account.is_some()
    }

    /// Check if the credential has a token.
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// Check if the credential has a valid token.
    pub fn has_valid_token(&self) -> bool {
        self.token.as_ref().is_some_and(|t| t.is_valid())
    }
}

impl KeyTrait for Credential {
    fn is_valid(&self) -> bool {
        // A credential is valid if it has a service account or a valid token
        self.service_account.is_some() || self.has_valid_token()
    }
}

/// AuthorizedUser holds OAuth2 user credentials.
#[derive(Clone, serde::Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct AuthorizedUser {
    /// The client ID.
    pub client_id: String,
    /// The client secret.
    pub client_secret: String,
    /// The refresh token.
    pub refresh_token: String,
}

/// CredentialFile represents the different types of Google credential files.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialFile {
    /// Service account with private key.
    ServiceAccount(ServiceAccount),
    /// External account for workload identity federation.
    ExternalAccount(ExternalAccount),
    /// Impersonated service account.
    ImpersonatedServiceAccount(ImpersonatedServiceAccount),
    /// Authorized user credentials.
    AuthorizedUser(AuthorizedUser),
}

impl CredentialFile {
    /// Parse credential file from bytes.
    pub fn from_slice(v: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(v)
            .map_err(|e| anyhow!("failed to parse credential file: {}", e))
    }

    /// Parse credential file from base64-encoded content.
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
    fn test_credential_file_deserialize() {
        // Test service account
        let sa_json = r#"{
            "type": "service_account",
            "private_key": "test_key",
            "client_email": "test@example.com"
        }"#;
        let cred = CredentialFile::from_slice(sa_json.as_bytes()).unwrap();
        match cred {
            CredentialFile::ServiceAccount(sa) => {
                assert_eq!(sa.client_email, "test@example.com");
            }
            _ => panic!("Expected ServiceAccount"),
        }

        // Test external account
        let ea_json = r#"{
            "type": "external_account",
            "audience": "test_audience",
            "subject_token_type": "test_type",
            "token_url": "https://example.com/token",
            "credential_source": {
                "file": "/path/to/file",
                "format": {
                    "type": "text"
                }
            }
        }"#;
        let cred = CredentialFile::from_slice(ea_json.as_bytes()).unwrap();
        assert!(matches!(cred, CredentialFile::ExternalAccount(_)));

        // Test authorized user
        let au_json = r#"{
            "type": "authorized_user",
            "client_id": "test_id",
            "client_secret": "test_secret",
            "refresh_token": "test_token"
        }"#;
        let cred = CredentialFile::from_slice(au_json.as_bytes()).unwrap();
        match cred {
            CredentialFile::AuthorizedUser(au) => {
                assert_eq!(au.client_id, "test_id");
            }
            _ => panic!("Expected AuthorizedUser"),
        }
    }

    #[test]
    fn test_credential_is_valid() {
        // Service account only
        let cred = Credential::with_service_account(ServiceAccount {
            client_email: "test@example.com".to_string(),
            private_key: "key".to_string(),
        });
        assert!(cred.is_valid());
        assert!(cred.has_service_account());
        assert!(!cred.has_token());

        // Valid token only
        let cred = Credential::with_token(Token {
            access_token: "test".to_string(),
            expires_at: Some(now() + chrono::TimeDelta::try_hours(1).unwrap()),
        });
        assert!(cred.is_valid());
        assert!(!cred.has_service_account());
        assert!(cred.has_token());
        assert!(cred.has_valid_token());

        // Invalid token only
        let cred = Credential::with_token(Token {
            access_token: String::new(),
            expires_at: None,
        });
        assert!(!cred.is_valid());
        assert!(!cred.has_valid_token());

        // Both service account and valid token
        let mut cred = Credential::with_service_account(ServiceAccount {
            client_email: "test@example.com".to_string(),
            private_key: "key".to_string(),
        });
        cred.token = Some(Token {
            access_token: "test".to_string(),
            expires_at: Some(now() + chrono::TimeDelta::try_hours(1).unwrap()),
        });
        assert!(cred.is_valid());
        assert!(cred.has_service_account());
        assert!(cred.has_valid_token());

        // Service account with expired token
        let mut cred = Credential::with_service_account(ServiceAccount {
            client_email: "test@example.com".to_string(),
            private_key: "key".to_string(),
        });
        cred.token = Some(Token {
            access_token: "test".to_string(),
            expires_at: Some(now() - chrono::TimeDelta::try_hours(1).unwrap()),
        });
        assert!(cred.is_valid()); // Still valid because of service account
        assert!(!cred.has_valid_token());
    }
}
