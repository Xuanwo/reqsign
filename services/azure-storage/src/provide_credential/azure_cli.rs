use std::path::PathBuf;
use std::process::Command;

use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential};
use serde::Deserialize;

use crate::credential::Credential;

/// AzureCliCredentialProvider provides credentials from Azure CLI
///
/// This provider reads tokens from Azure CLI's local storage or invokes
/// `az account get-access-token` to retrieve fresh tokens.
#[derive(Clone, Debug, Default)]
pub struct AzureCliCredentialProvider {}

impl AzureCliCredentialProvider {
    pub fn new() -> Self {
        Self {}
    }

    /// Get the Azure CLI config directory
    #[allow(dead_code)]
    fn get_azure_config_dir(&self) -> PathBuf {
        if let Ok(config_dir) = std::env::var("AZURE_CONFIG_DIR") {
            return PathBuf::from(config_dir);
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                return PathBuf::from(userprofile).join(".azure");
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(home).join(".azure");
            }
        }

        // Fallback to current directory
        PathBuf::from(".azure")
    }

    /// Execute `az account get-access-token` command
    async fn get_access_token_from_cli(
        &self,
        resource: &str,
    ) -> Result<AzureCliToken, reqsign_core::Error> {
        let output = Command::new("az")
            .args([
                "account",
                "get-access-token",
                "--resource",
                resource,
                "--output",
                "json",
            ])
            .output()
            .map_err(|e| {
                reqsign_core::Error::unexpected(format!(
                    "Failed to execute Azure CLI command: {}",
                    e
                ))
            })?;

        if !output.status.success() {
            return Err(reqsign_core::Error::credential_invalid(format!(
                "Azure CLI command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let token: AzureCliToken = serde_json::from_slice(&output.stdout).map_err(|e| {
            reqsign_core::Error::unexpected(format!("Failed to parse Azure CLI output: {}", e))
        })?;

        Ok(token)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureCliToken {
    access_token: String,
    expires_on: Option<String>,
    #[serde(rename = "expires_on")]
    expires_on_timestamp: Option<i64>,
    #[allow(dead_code)]
    subscription: Option<String>,
    #[allow(dead_code)]
    tenant: Option<String>,
    #[allow(dead_code)]
    token_type: String,
}

#[async_trait]
impl ProvideCredential for AzureCliCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(
        &self,
        _ctx: &Context,
    ) -> Result<Option<Self::Credential>, reqsign_core::Error> {
        // For Azure Storage, we need the storage resource
        let resource = "https://storage.azure.com/";

        // Try to get access token from Azure CLI
        match self.get_access_token_from_cli(resource).await {
            Ok(token) => {
                // Calculate expiration time
                let expires_on = if let Some(timestamp) = token.expires_on_timestamp {
                    Some(chrono::DateTime::from_timestamp(timestamp, 0).unwrap())
                } else if let Some(expires_str) = token.expires_on {
                    // Parse the string format "2023-10-31 21:59:10.000000"
                    chrono::NaiveDateTime::parse_from_str(&expires_str, "%Y-%m-%d %H:%M:%S%.f")
                        .ok()
                        .map(|dt| chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc))
                } else {
                    None
                };

                Ok(Some(Credential::with_bearer_token(
                    &token.access_token,
                    expires_on,
                )))
            }
            Err(_) => {
                // Azure CLI is not available or user is not logged in
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_azure_config_dir() {
        let provider = AzureCliCredentialProvider::new();
        let config_dir = provider.get_azure_config_dir();

        // Should return a valid path
        assert!(!config_dir.as_os_str().is_empty());

        // On Unix systems, should contain .azure
        #[cfg(not(target_os = "windows"))]
        assert!(config_dir.to_string_lossy().contains(".azure"));
    }

    #[test]
    fn test_parse_azure_cli_token() {
        let json = r#"{
            "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM...",
            "expiresOn": "2023-10-31 21:59:10.000000",
            "expires_on": 1698760750,
            "subscription": "0b1f6471-1bf0-4dda-aec3-cb9272f09590",
            "tenant": "54826b22-38d6-4fb2-bad9-b7b93a3e9c5a",
            "tokenType": "Bearer"
        }"#;

        let token: AzureCliToken = serde_json::from_str(json).unwrap();
        assert_eq!(
            token.access_token,
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM..."
        );
        assert_eq!(token.expires_on_timestamp, Some(1698760750));
        assert_eq!(token.token_type, "Bearer");
    }

    #[tokio::test]
    async fn test_provide_credential_azure_cli_not_available() {
        // When Azure CLI is not installed or user is not logged in,
        // the provider should return None instead of error
        let provider = AzureCliCredentialProvider::new();
        let ctx = reqsign_core::Context::new(
            reqsign_file_read_tokio::TokioFileRead,
            reqsign_http_send_reqwest::ReqwestHttpSend::default(),
        );

        // This test assumes Azure CLI is not set up in test environment
        // In real usage, if Azure CLI is available and logged in, this would return Some(credential)
        let result = provider.provide_credential(&ctx).await;

        // Should not error out
        assert!(result.is_ok());
    }
}
