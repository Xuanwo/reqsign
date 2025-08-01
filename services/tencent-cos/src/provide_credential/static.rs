use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, Result};

/// StaticCredentialProvider provides static credentials that are provided at initialization time.
#[derive(Debug)]
pub struct StaticCredentialProvider {
    credential: Credential,
}

impl StaticCredentialProvider {
    /// Create a new StaticCredentialProvider with the given credentials.
    pub fn new(secret_id: &str, secret_key: &str) -> Self {
        Self {
            credential: Credential {
                secret_id: secret_id.to_string(),
                secret_key: secret_key.to_string(),
                security_token: None,
                expires_in: None,
            },
        }
    }

    /// Create a new StaticCredentialProvider with security token.
    pub fn with_security_token(secret_id: &str, secret_key: &str, security_token: &str) -> Self {
        Self {
            credential: Credential {
                secret_id: secret_id.to_string(),
                secret_key: secret_key.to_string(),
                security_token: Some(security_token.to_string()),
                expires_in: None,
            },
        }
    }
}

#[async_trait]
impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        Ok(Some(self.credential.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;

    #[tokio::test]
    async fn test_static_credential_provider() -> anyhow::Result<()> {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

        let provider = StaticCredentialProvider::new("test_secret_id", "test_secret_key");
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.secret_id, "test_secret_id");
        assert_eq!(cred.secret_key, "test_secret_key");
        assert!(cred.security_token.is_none());

        // Test with security token
        let provider = StaticCredentialProvider::with_security_token(
            "test_secret_id",
            "test_secret_key",
            "test_security_token",
        );
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.secret_id, "test_secret_id");
        assert_eq!(cred.secret_key, "test_secret_key");
        assert_eq!(cred.security_token, Some("test_security_token".to_string()));

        Ok(())
    }
}
