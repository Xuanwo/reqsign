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
    pub fn new(user: &str, tenancy: &str, key_file: &str, fingerprint: &str) -> Self {
        Self {
            credential: Credential {
                user: user.to_string(),
                tenancy: tenancy.to_string(),
                key_file: key_file.to_string(),
                fingerprint: fingerprint.to_string(),
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

        let provider = StaticCredentialProvider::new(
            "test_user",
            "test_tenancy",
            "/path/to/key",
            "test_fingerprint",
        );
        let cred = provider.provide_credential(&ctx).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.user, "test_user");
        assert_eq!(cred.tenancy, "test_tenancy");
        assert_eq!(cred.key_file, "/path/to/key");
        assert_eq!(cred.fingerprint, "test_fingerprint");
        assert!(cred.expires_in.is_none());

        Ok(())
    }
}
