use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, Result};

/// StaticCredentialProvider provides static Aliyun credentials.
///
/// This provider is used when you have the access key ID and access key secret
/// directly and want to use them without any dynamic loading.
#[derive(Debug, Clone)]
pub struct StaticCredentialProvider {
    access_key_id: String,
    access_key_secret: String,
    security_token: Option<String>,
}

impl StaticCredentialProvider {
    /// Create a new StaticCredentialProvider with access key ID and access key secret.
    pub fn new(access_key_id: impl Into<String>, access_key_secret: impl Into<String>) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            access_key_secret: access_key_secret.into(),
            security_token: None,
        }
    }

    /// Set the security token.
    pub fn with_security_token(mut self, token: impl Into<String>) -> Self {
        self.security_token = Some(token.into());
        self
    }
}

#[async_trait]
impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _: &Context) -> Result<Option<Self::Credential>> {
        Ok(Some(Credential {
            access_key_id: self.access_key_id.clone(),
            access_key_secret: self.access_key_secret.clone(),
            security_token: self.security_token.clone(),
            expires_in: None,
        }))
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

        // Test with basic credentials
        let provider = StaticCredentialProvider::new("test_access_key", "test_secret_key");
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "test_access_key");
        assert_eq!(cred.access_key_secret, "test_secret_key");
        assert!(cred.security_token.is_none());

        // Test with security token
        let provider = StaticCredentialProvider::new("test_access_key", "test_secret_key")
            .with_security_token("test_security_token");
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "test_access_key");
        assert_eq!(cred.access_key_secret, "test_secret_key");
        assert_eq!(cred.security_token, Some("test_security_token".to_string()));

        Ok(())
    }
}
