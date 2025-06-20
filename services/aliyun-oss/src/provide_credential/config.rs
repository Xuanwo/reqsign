use crate::{Config, Credential};
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential};
use std::sync::Arc;

/// ConfigCredentialProvider loads credential from static config.
#[derive(Debug)]
pub struct ConfigCredentialProvider {
    config: Arc<Config>,
}

impl ConfigCredentialProvider {
    /// Create a new `ConfigCredentialProvider` instance.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ProvideCredential for ConfigCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> reqsign_core::Result<Option<Self::Credential>> {
        if let (Some(access_key_id), Some(access_key_secret)) =
            (&self.config.access_key_id, &self.config.access_key_secret)
        {
            Ok(Some(Credential {
                access_key_id: access_key_id.clone(),
                access_key_secret: access_key_secret.clone(),
                security_token: self.config.security_token.clone(),
                expires_in: None,
            }))
        } else {
            Ok(None)
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
    async fn test_config_loader_with_credentials() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let config = Config {
            access_key_id: Some("test_access_key".to_string()),
            access_key_secret: Some("test_secret_key".to_string()),
            security_token: Some("test_token".to_string()),
            ..Default::default()
        };

        let loader = ConfigCredentialProvider::new(Arc::new(config));
        let credential = loader.provide_credential(&ctx).await.unwrap().unwrap();

        assert_eq!(credential.access_key_id, "test_access_key");
        assert_eq!(credential.access_key_secret, "test_secret_key");
        assert_eq!(credential.security_token, Some("test_token".to_string()));
    }

    #[tokio::test]
    async fn test_config_loader_without_credentials() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let config = Config::default();
        let loader = ConfigCredentialProvider::new(Arc::new(config));
        let credential = loader.provide_credential(&ctx).await.unwrap();

        assert!(credential.is_none());
    }
}
