use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential};
use std::fmt::{self, Debug};

/// A chain of credential providers that will be tried in order.
pub struct ProvideCredentialChain {
    providers: Vec<Box<dyn ProvideCredential<Credential = Credential>>>,
}

impl ProvideCredentialChain {
    /// Create a new empty credential provider chain.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Add a credential provider to the chain.
    pub fn push(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.providers.push(Box::new(provider));
        self
    }

    /// Create a credential provider chain from a vector of providers.
    pub fn from_vec(providers: Vec<Box<dyn ProvideCredential<Credential = Credential>>>) -> Self {
        Self { providers }
    }
}

impl Default for ProvideCredentialChain {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for ProvideCredentialChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvideCredentialChain")
            .field("providers_count", &self.providers.len())
            .finish()
    }
}

#[async_trait]
impl ProvideCredential for ProvideCredentialChain {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        for provider in &self.providers {
            log::debug!("Trying credential provider: {:?}", provider);

            match provider.provide_credential(ctx).await {
                Ok(Some(cred)) => {
                    log::debug!("Successfully loaded credential from provider: {:?}", provider);
                    return Ok(Some(cred));
                }
                Ok(None) => {
                    log::debug!("No credential found in provider: {:?}", provider);
                    continue;
                }
                Err(e) => {
                    log::warn!(
                        "Error loading credential from provider {:?}: {:?}",
                        provider,
                        e
                    );
                    // Continue to next provider on error
                    continue;
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSuccessProvider {
        access_key: String,
        secret_key: String,
    }

    #[async_trait]
    impl ProvideCredential for MockSuccessProvider {
        type Credential = Credential;

        async fn provide_credential(
            &self,
            _ctx: &Context,
        ) -> anyhow::Result<Option<Self::Credential>> {
            Ok(Some(Credential {
                access_key_id: self.access_key.clone(),
                secret_access_key: self.secret_key.clone(),
                session_token: None,
                expires_in: None,
            }))
        }
    }

    impl Debug for MockSuccessProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockSuccessProvider").finish()
        }
    }

    struct MockFailProvider;

    #[async_trait]
    impl ProvideCredential for MockFailProvider {
        type Credential = Credential;

        async fn provide_credential(
            &self,
            _ctx: &Context,
        ) -> anyhow::Result<Option<Self::Credential>> {
            Err(anyhow::anyhow!("Mock provider failed"))
        }
    }

    impl Debug for MockFailProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockFailProvider").finish()
        }
    }

    struct MockEmptyProvider;

    #[async_trait]
    impl ProvideCredential for MockEmptyProvider {
        type Credential = Credential;

        async fn provide_credential(
            &self,
            _ctx: &Context,
        ) -> anyhow::Result<Option<Self::Credential>> {
            Ok(None)
        }
    }

    impl Debug for MockEmptyProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockEmptyProvider").finish()
        }
    }

    #[tokio::test]
    async fn test_chain_returns_first_success() {
        use reqsign_core::StaticEnv;
        use reqsign_file_read_tokio::TokioFileRead;
        use reqsign_http_send_reqwest::ReqwestHttpSend;
        use std::collections::HashMap;

        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let chain = ProvideCredentialChain::new()
            .push(MockFailProvider)
            .push(MockEmptyProvider)
            .push(MockSuccessProvider {
                access_key: "test_key".to_string(),
                secret_key: "test_secret".to_string(),
            })
            .push(MockSuccessProvider {
                access_key: "should_not_be_used".to_string(),
                secret_key: "should_not_be_used".to_string(),
            });

        let result = chain.provide_credential(&ctx).await.unwrap();
        assert!(result.is_some());

        let cred = result.unwrap();
        assert_eq!(cred.access_key_id, "test_key");
        assert_eq!(cred.secret_access_key, "test_secret");
    }

    #[tokio::test]
    async fn test_chain_returns_none_when_all_fail() {
        use reqsign_core::StaticEnv;
        use reqsign_file_read_tokio::TokioFileRead;
        use reqsign_http_send_reqwest::ReqwestHttpSend;
        use std::collections::HashMap;

        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let chain = ProvideCredentialChain::new()
            .push(MockFailProvider)
            .push(MockEmptyProvider)
            .push(MockFailProvider);

        let result = chain.provide_credential(&ctx).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_empty_chain_returns_none() {
        use reqsign_core::StaticEnv;
        use reqsign_file_read_tokio::TokioFileRead;
        use reqsign_http_send_reqwest::ReqwestHttpSend;
        use std::collections::HashMap;

        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let chain = ProvideCredentialChain::new();

        let result = chain.provide_credential(&ctx).await.unwrap();
        assert!(result.is_none());
    }
}

