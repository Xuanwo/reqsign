use crate::{constants::*, Credential};
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, Result};

/// EnvCredentialProvider loads AWS credentials from environment variables.
///
/// This provider looks for the following environment variables:
/// - `AWS_ACCESS_KEY_ID`: The AWS access key ID
/// - `AWS_SECRET_ACCESS_KEY`: The AWS secret access key
/// - `AWS_SESSION_TOKEN`: The AWS session token (optional)
#[derive(Debug, Default)]
pub struct EnvCredentialProvider;

impl EnvCredentialProvider {
    /// Create a new EnvCredentialProvider.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProvideCredential for EnvCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let envs = ctx.env_vars();

        let access_key_id = envs.get(AWS_ACCESS_KEY_ID);
        let secret_access_key = envs.get(AWS_SECRET_ACCESS_KEY);

        match (access_key_id, secret_access_key) {
            (Some(ak), Some(sk)) => Ok(Some(Credential {
                access_key_id: ak.clone(),
                secret_access_key: sk.clone(),
                session_token: envs.get(AWS_SESSION_TOKEN).cloned(),
                expires_in: None,
            })),
            _ => Ok(None),
        }
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
    async fn test_env_credential_provider() -> anyhow::Result<()> {
        // Test with valid credentials
        let envs = HashMap::from([
            (AWS_ACCESS_KEY_ID.to_string(), "test_access_key".to_string()),
            (
                AWS_SECRET_ACCESS_KEY.to_string(),
                "test_secret_key".to_string(),
            ),
        ]);

        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default()).with_env(StaticEnv {
            home_dir: None,
            envs,
        });

        let provider = EnvCredentialProvider::new();
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "test_access_key");
        assert_eq!(cred.secret_access_key, "test_secret_key");
        assert!(cred.session_token.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_env_credential_provider_with_session_token() -> anyhow::Result<()> {
        let envs = HashMap::from([
            (AWS_ACCESS_KEY_ID.to_string(), "test_access_key".to_string()),
            (
                AWS_SECRET_ACCESS_KEY.to_string(),
                "test_secret_key".to_string(),
            ),
            (
                AWS_SESSION_TOKEN.to_string(),
                "test_session_token".to_string(),
            ),
        ]);

        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default()).with_env(StaticEnv {
            home_dir: None,
            envs,
        });

        let provider = EnvCredentialProvider::new();
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "test_access_key");
        assert_eq!(cred.secret_access_key, "test_secret_key");
        assert_eq!(cred.session_token, Some("test_session_token".to_string()));

        Ok(())
    }

    #[tokio::test]
    async fn test_env_credential_provider_missing_credentials() -> anyhow::Result<()> {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

        let provider = EnvCredentialProvider::new();
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_env_credential_provider_partial_credentials() -> anyhow::Result<()> {
        // Only access key ID
        let envs = HashMap::from([(AWS_ACCESS_KEY_ID.to_string(), "test_access_key".to_string())]);

        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default()).with_env(StaticEnv {
            home_dir: None,
            envs,
        });

        let provider = EnvCredentialProvider::new();
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_none());

        Ok(())
    }
}
