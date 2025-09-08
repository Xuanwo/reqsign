use crate::provide_credential::{
    AssumeRoleWithWebIdentityCredentialProvider, EnvCredentialProvider,
};
use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};

/// Default loader for Tencent COS.
///
/// This loader will try to load credentials in the following order:
/// 1. From environment variables
/// 2. From AssumeRoleWithWebIdentity
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    chain: ProvideCredentialChain<Credential>,
}

impl Default for DefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCredentialProvider {
    /// Create a builder to configure the default credential chain.
    pub fn builder() -> DefaultCredentialProviderBuilder {
        DefaultCredentialProviderBuilder::default()
    }

    /// Create a new DefaultCredentialProvider using the default chain.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create with a custom credential chain.
    pub fn with_chain(chain: ProvideCredentialChain<Credential>) -> Self {
        Self { chain }
    }

    /// Add a credential provider to the front of the default chain.
    ///
    /// This allows adding a high-priority credential source that will be tried
    /// before all other providers in the default chain.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_tencent_cos::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new("secret_id", "secret_key"));
    /// ```
    pub fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.chain = self.chain.push_front(provider);
        self
    }
}

/// Builder for `DefaultCredentialProvider`.
///
/// - Use `configure_*` to customize a provider.
/// - Use `disable_*(bool)` to disable (true) or ensure enabled (false).
/// - Call `build()` to construct the provider in the default order.
#[derive(Default)]
pub struct DefaultCredentialProviderBuilder {
    env: Option<EnvCredentialProvider>,
    assume_role: Option<AssumeRoleWithWebIdentityCredentialProvider>,
}

impl DefaultCredentialProviderBuilder {
    /// Create a new builder with default state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the environment credential provider.
    pub fn configure_env<F>(mut self, f: F) -> Self
    where
        F: FnOnce(EnvCredentialProvider) -> EnvCredentialProvider,
    {
        let p = self.env.take().unwrap_or_default();
        self.env = Some(f(p));
        self
    }

    /// Disable (true) or ensure enabled (false) the environment provider.
    pub fn disable_env(mut self, disable: bool) -> Self {
        if disable {
            self.env = None;
        } else if self.env.is_none() {
            self.env = Some(EnvCredentialProvider::new());
        }
        self
    }

    /// Configure the web-identity assume-role credential provider.
    pub fn configure_assume_role<F>(mut self, f: F) -> Self
    where
        F: FnOnce(AssumeRoleWithWebIdentityCredentialProvider) ->
            AssumeRoleWithWebIdentityCredentialProvider,
    {
        let p = self
            .assume_role
            .take()
            .unwrap_or_default();
        self.assume_role = Some(f(p));
        self
    }

    /// Disable (true) or ensure enabled (false) the web-identity assume-role provider.
    pub fn disable_assume_role(mut self, disable: bool) -> Self {
        if disable {
            self.assume_role = None;
        } else if self.assume_role.is_none() {
            self.assume_role = Some(AssumeRoleWithWebIdentityCredentialProvider::new());
        }
        self
    }

    /// Build the `DefaultCredentialProvider` with the configured options.
    pub fn build(self) -> DefaultCredentialProvider {
        let mut chain = ProvideCredentialChain::new();
        if let Some(p) = self.env {
            chain = chain.push(p);
        } else {
            chain = chain.push(EnvCredentialProvider::new());
        }
        if let Some(p) = self.assume_role {
            chain = chain.push(p);
        } else {
            chain = chain.push(AssumeRoleWithWebIdentityCredentialProvider::new());
        }

        DefaultCredentialProvider::with_chain(chain)
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
    use reqsign_core::{OsEnv, StaticEnv};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_default_loader_without_env() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let loader = DefaultCredentialProvider::new();
        let credential = loader.provide_credential(&ctx).await.unwrap();

        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn test_default_loader_with_env() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (TENCENTCLOUD_SECRET_ID.to_string(), "secret_id".to_string()),
                (
                    TENCENTCLOUD_SECRET_KEY.to_string(),
                    "secret_key".to_string(),
                ),
            ]),
        });

        let loader = DefaultCredentialProvider::new();
        let credential = loader.provide_credential(&ctx).await.unwrap().unwrap();

        assert_eq!("secret_id", credential.secret_id);
        assert_eq!("secret_key", credential.secret_key);
    }

    #[tokio::test]
    async fn test_default_loader_with_security_token() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (TKE_SECRET_ID.to_string(), "secret_id".to_string()),
                (TKE_SECRET_KEY.to_string(), "secret_key".to_string()),
                (TENCENTCLOUD_TOKEN.to_string(), "security_token".to_string()),
            ]),
        });

        let loader = DefaultCredentialProvider::new();
        let credential = loader.provide_credential(&ctx).await.unwrap().unwrap();

        assert_eq!("secret_id", credential.secret_id);
        assert_eq!("secret_key", credential.secret_key);
        assert_eq!("security_token", credential.security_token.unwrap());
    }
}
