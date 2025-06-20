use crate::provide_credential::{AssumeRoleWithOidcCredentialProvider, ConfigCredentialProvider};
use crate::{Config, Credential};
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};
use std::sync::Arc;

/// DefaultCredentialProvider is a loader that will try to load credential via default chains.
///
/// Resolution order:
///
/// 1. Static configuration (access_key_id and access_key_secret)
/// 2. Assume Role with OIDC
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    chain: ProvideCredentialChain<Credential>,
}

impl DefaultCredentialProvider {
    /// Create a new `DefaultCredentialProvider` instance.
    pub fn new(config: Arc<Config>) -> Self {
        let chain = ProvideCredentialChain::new()
            .push(ConfigCredentialProvider::new(config.clone()))
            .push(AssumeRoleWithOidcCredentialProvider::new(config));

        Self { chain }
    }
}

#[async_trait]
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        self.chain.provide_credential(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use reqsign_core::StaticEnv;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_default_loader_without_config() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let config = Config::default();
        let loader = DefaultCredentialProvider::new(Arc::new(config));
        let credential = loader.provide_credential(&ctx).await.unwrap();

        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn test_default_loader_with_config() {
        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (
                    ALIBABA_CLOUD_ACCESS_KEY_ID.to_string(),
                    "access_key_id".to_string(),
                ),
                (
                    ALIBABA_CLOUD_ACCESS_KEY_SECRET.to_string(),
                    "secret_access_key".to_string(),
                ),
            ]),
        });

        let config = Config::default().from_env(&ctx);
        let loader = DefaultCredentialProvider::new(Arc::new(config));
        let credential = loader.provide_credential(&ctx).await.unwrap().unwrap();

        assert_eq!("access_key_id", credential.access_key_id);
        assert_eq!("secret_access_key", credential.access_key_secret);
    }
}
