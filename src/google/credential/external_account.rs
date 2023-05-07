pub use credential_source::{
    CredentialSource, EnvironmentSourcedCredentials, ExecutableSourcedCredentials,
    FileSourcedCredentials, FormatType, UrlSourcedCredentials,
};
use serde::Deserialize;

/// Credential is the file which stores service account's client_id and private key.
///
/// Reference: https://google.aip.dev/auth/4117#expected-behavior.
#[derive(Clone, Deserialize)]
#[cfg_attr(test, derive(Debug))]
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

#[derive(Clone, Deserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct ServiceAccountImpersonation {
    pub token_lifetime_seconds: Option<usize>,
}

/// This module describes the types of credential sources an external account
/// might use to generate an ID token.
///
/// For reference, see <https://google.aip.dev/auth/4117>.
mod credential_source {
    use std::collections::HashMap;

    use anyhow::{bail, Result};
    use serde::Deserialize;
    use serde_json::Value;

    #[derive(Clone, Deserialize)]
    #[cfg_attr(test, derive(Debug))]
    #[serde(untagged)]
    pub enum CredentialSource {
        EnvironmentSourced(EnvironmentSourcedCredentials),
        ExecutableSourced {
            executable: ExecutableSourcedCredentials,
        },
        FileSourced(FileSourcedCredentials),
        UrlSourced(UrlSourcedCredentials),
    }

    #[derive(Clone, Debug, Default, Deserialize)]
    #[serde(rename_all = "snake_case", tag = "type")]
    pub enum FormatType {
        #[default]
        Text,
        Json {
            subject_token_field_name: String,
        },
    }

    impl FormatType {
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

    #[derive(Clone, Deserialize)]
    #[cfg_attr(test, derive(Debug))]
    pub struct EnvironmentSourcedCredentials {
        pub environment_id: String,
        pub region_url: String,
        pub regional_red_verification_url: String,
        pub url: Option<String>,
        pub imdsv2_session_token_url: Option<String>,
    }

    #[derive(Clone, Deserialize)]
    #[cfg_attr(test, derive(Debug))]
    pub struct ExecutableSourcedCredentials {
        pub command: String,
        pub timeout_millis: Option<i64>,
        pub output_file: Option<String>,
    }

    #[derive(Clone, Deserialize)]
    #[cfg_attr(test, derive(Debug))]
    pub struct FileSourcedCredentials {
        pub file: String,
        #[serde(default)]
        pub format: FormatType,
    }

    #[derive(Clone, Deserialize)]
    #[cfg_attr(test, derive(Debug))]
    pub struct UrlSourcedCredentials {
        pub url: String,
        #[serde(default)]
        pub headers: HashMap<String, String>,
        #[serde(default)]
        pub format: FormatType,
    }
}
