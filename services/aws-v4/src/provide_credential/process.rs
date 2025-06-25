use crate::Credential;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ini::Ini;
use log::debug;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;
use std::process::Stdio;
use tokio::process::Command;

/// Process Credentials Provider
///
/// This provider executes an external process to retrieve credentials.
/// The process must output JSON in a specific format to stdout.
///
/// # Configuration
/// Process credentials are typically configured in ~/.aws/config:
/// ```ini
/// [profile my-process-profile]
/// credential_process = /path/to/credential/helper --arg1 value1
/// ```
///
/// # Output Format
/// The process must output JSON with the following structure:
/// ```json
/// {
///   "Version": 1,
///   "AccessKeyId": "access_key",
///   "SecretAccessKey": "secret_key",
///   "SessionToken": "session_token",
///   "Expiration": "2023-12-01T00:00:00Z"
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ProcessCredentialProvider {
    profile: Option<String>,
    command: Option<String>,
}

impl Default for ProcessCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessCredentialProvider {
    /// Create a new process credential provider
    pub fn new() -> Self {
        Self {
            profile: None,
            command: None,
        }
    }

    /// Set the profile name to use
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set the command directly
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    async fn get_command(&self, ctx: &Context) -> Result<String> {
        // If command is directly provided, use it
        if let Some(cmd) = &self.command {
            return Ok(cmd.clone());
        }

        // Otherwise, load from config file
        let profile_name = self.profile.as_deref().unwrap_or("default");
        self.load_command_from_config(ctx, profile_name).await
    }

    async fn load_command_from_config(&self, ctx: &Context, profile: &str) -> Result<String> {
        // Load AWS config file
        let config_path = ctx
            .env_var("AWS_CONFIG_FILE")
            .unwrap_or_else(|| "~/.aws/config".to_string());

        let expanded_path = if config_path.starts_with("~/") {
            match ctx.expand_home_dir(&config_path) {
                Some(expanded) => expanded,
                None => return Err(Error::config_invalid("failed to expand home directory")),
            }
        } else {
            config_path
        };

        let content = ctx.file_read(&expanded_path).await.map_err(|_| {
            Error::config_invalid(format!("failed to read config file: {}", expanded_path))
        })?;

        let conf = Ini::load_from_str(&String::from_utf8_lossy(&content))
            .map_err(|e| Error::config_invalid(format!("failed to parse config file: {}", e)))?;

        let profile_section = if profile == "default" {
            profile.to_string()
        } else {
            format!("profile {}", profile)
        };

        let section = conf.section(Some(profile_section)).ok_or_else(|| {
            Error::config_invalid(format!("profile '{}' not found in config", profile))
        })?;

        section
            .get("credential_process")
            .ok_or_else(|| {
                Error::config_invalid(format!(
                    "credential_process not found in profile '{}'",
                    profile
                ))
            })
            .map(|s| s.to_string())
    }

    async fn execute_process(&self, command: &str) -> Result<ProcessCredentialOutput> {
        debug!("executing credential process: {}", command);

        // Parse command into program and arguments
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return Err(Error::config_invalid(
                "credential_process command is empty".to_string(),
            ));
        }

        let program = parts[0];
        let args = &parts[1..];

        // Execute the process
        let output = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                Error::unexpected(format!("failed to execute credential process: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::unexpected(format!(
                "credential process failed with status {}: {}",
                output.status, stderr
            )));
        }

        // Parse the output
        let stdout = &output.stdout;
        let creds: ProcessCredentialOutput = serde_json::from_slice(stdout).map_err(|e| {
            Error::unexpected(format!("failed to parse credential process output: {}", e))
        })?;

        // Validate version
        if creds.version != 1 {
            return Err(Error::unexpected(format!(
                "unsupported credential process version: {}",
                creds.version
            )));
        }

        Ok(creds)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ProcessCredentialOutput {
    version: u32,
    access_key_id: String,
    secret_access_key: String,
    #[serde(default)]
    session_token: Option<String>,
    #[serde(default)]
    expiration: Option<String>,
}

#[async_trait]
impl ProvideCredential for ProcessCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let command = match self.get_command(ctx).await {
            Ok(cmd) => cmd,
            Err(_) => {
                debug!("no credential_process configured");
                return Ok(None);
            }
        };

        let output = self.execute_process(&command).await?;

        let expires_in = if let Some(exp_str) = &output.expiration {
            Some(exp_str.parse::<DateTime<Utc>>().map_err(|e| {
                Error::unexpected(format!("failed to parse expiration time: {}", e))
            })?)
        } else {
            None
        };

        Ok(Some(Credential {
            access_key_id: output.access_key_id,
            secret_access_key: output.secret_access_key,
            session_token: output.session_token,
            expires_in,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::StaticEnv;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_process_provider_no_config() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: Some(std::path::PathBuf::from("/home/test")),
            envs: HashMap::new(),
        });

        let provider = ProcessCredentialProvider::new();
        let result = provider.provide_credential(&ctx).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_process_provider_with_command() {
        let _provider = ProcessCredentialProvider::new()
            .with_command("echo '{\"Version\": 1, \"AccessKeyId\": \"test_key\", \"SecretAccessKey\": \"test_secret\"}'");

        // This test would need a real command that outputs valid JSON
        // In practice, you'd use a mock or test helper
    }

    #[test]
    fn test_parse_process_output() {
        let json = r#"{
            "Version": 1,
            "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "token",
            "Expiration": "2023-12-01T00:00:00Z"
        }"#;

        let output: ProcessCredentialOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.version, 1);
        assert_eq!(output.access_key_id, "ASIAIOSFODNN7EXAMPLE");
        assert_eq!(output.session_token, Some("token".to_string()));
    }
}
