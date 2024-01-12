//! An external account.

use anyhow::bail;
use anyhow::Result;
pub use credential_source::CredentialSource;
pub use credential_source::FileSourcedCredentials;
pub use credential_source::UrlSourcedCredentials;
use serde::Deserialize;

use serde_json::Value;
/// Credential is the file which stores service account's client_id and private key.
///
/// Reference: https://google.aip.dev/auth/4117#expected-behavior.
#[derive(Clone, Deserialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename_all = "snake_case")]
pub struct ExternalAccount {
    /// This is the STS audience containing the resource name for the workload
    /// identity pool and provider identifier.
    pub audience: String,
    /// This is the STS subject token type.
    pub subject_token_type: String,
    /// This is the URL for the service account impersonation request.
    /// If not present the STS access token should be used without impersonation.
    pub service_account_impersonation_url: Option<String>,
    /// This object defines additional service account impersonation options.
    pub service_account_impersonation: Option<ServiceAccountImpersonation>,
    /// This is the STS token exchange endpoint.
    pub token_url: String,
    /// This object defines the mechanism used to retrieve the external credential
    /// from the local environment so that it can be exchanged for a GCP access
    /// token via the STS endpoint.
    pub credential_source: CredentialSource,
}

/// A source format type.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum FormatType {
    /// A raw token.
    #[default]
    Text,
    /// A JSON payload containing the token.
    Json {
        /// The field containing the token.
        subject_token_field_name: String,
    },
}

impl FormatType {
    /// Parse a slice of bytes as the expected format.
    pub fn parse(&self, slice: &[u8]) -> Result<String> {
        match &self {
            Self::Text => Ok(String::from_utf8(slice.to_vec())?),
            Self::Json {
                subject_token_field_name,
            } => {
                let Value::Object(mut obj) = serde_json::from_slice(slice)? else {
                    bail!("failed to decode token JSON");
                };

                match obj.remove(subject_token_field_name) {
                    Some(Value::String(access_token)) => Ok(access_token),
                    _ => bail!("JSON missing token field {subject_token_field_name}"),
                }
            }
        }
    }
}

/// Extra information about the impersonation exchange.
#[derive(Clone, Deserialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename_all = "snake_case")]
pub struct ServiceAccountImpersonation {
    /// The lifetime in seconds to be used when exchanging the STS token.
    pub token_lifetime_seconds: Option<usize>,
}

/// This module describes the types of credential sources an external account
/// might use to generate an ID token.
///
/// For reference, see <https://google.aip.dev/auth/4117>.
mod credential_source {
    use super::FormatType;
    use serde::Deserialize;
    use std::collections::HashMap;

    /// An instruction on how to load a token for the local environment.
    ///
    /// **NOTE:** environment and executable sources are not yet supported.
    #[derive(Clone, Deserialize)]
    #[cfg_attr(test, derive(Debug))]
    #[serde(untagged)]
    pub enum CredentialSource {
        /// An OIDC token provided via file.
        FileSourced(FileSourcedCredentials),
        /// An OIDC token provided via a URL.
        UrlSourced(UrlSourcedCredentials),
    }

    /// A file sourced OIDC token.
    #[derive(Clone, Deserialize)]
    #[cfg_attr(test, derive(Debug))]
    #[serde(rename_all = "snake_case")]
    pub struct FileSourcedCredentials {
        /// The file containing the token.
        pub file: String,
        /// The format of the file.
        #[serde(default)]
        pub format: FormatType,
    }

    /// A URL sourced OIDC token. Used by Azure and other OIDC providers.
    #[derive(Clone, Deserialize)]
    #[cfg_attr(test, derive(Debug))]
    #[serde(rename_all = "snake_case")]
    pub struct UrlSourcedCredentials {
        /// The URL to where the POST request is made.
        pub url: String,
        /// The headers to be injected in the request.
        #[serde(default)]
        pub headers: HashMap<String, String>,
        /// The format of the response payload.
        #[serde(default)]
        pub format: FormatType,
    }
}
