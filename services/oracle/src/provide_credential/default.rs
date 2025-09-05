use crate::provide_credential::{ConfigFileCredentialProvider, EnvCredentialProvider};
use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};

/// Default loader for Oracle Cloud Infrastructure.
///
/// This loader will try to load credentials in the following order:
/// 1. From environment variables
/// 2. From the default Oracle config file (~/.oci/config)
#[derive(Debug, Default)]
pub struct DefaultCredentialProvider {
    chain: ProvideCredentialChain<Credential>,
    env_provider: EnvCredentialProvider,
    config_file_provider: ConfigFileCredentialProvider,
}

impl DefaultCredentialProvider {
    /// Create a new DefaultCredentialProvider
    pub fn new() -> Self {
        let env_provider = EnvCredentialProvider::new();
        let config_file_provider = ConfigFileCredentialProvider::new();

        let mut provider = Self {
            chain: ProvideCredentialChain::new(),
            env_provider,
            config_file_provider,
        };

        provider.rebuild_chain();
        provider
    }

    /// Rebuild the internal chain based on current provider configurations.
    fn rebuild_chain(&mut self) {
        self.chain = ProvideCredentialChain::new()
            .push(self.env_provider.clone())
            .push(self.config_file_provider.clone());
    }

    /// Configure the environment credential provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_oracle::DefaultCredentialProvider;
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .configure_env(|p| p.with_disabled(true));
    /// ```
    pub fn configure_env<F>(mut self, f: F) -> Self
    where
        F: FnOnce(EnvCredentialProvider) -> EnvCredentialProvider,
    {
        self.env_provider = f(self.env_provider);
        self.rebuild_chain();
        self
    }

    /// Configure the config file credential provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_oracle::DefaultCredentialProvider;
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .configure_config_file(|p| p.with_disabled(true));
    /// ```
    pub fn configure_config_file<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ConfigFileCredentialProvider) -> ConfigFileCredentialProvider,
    {
        self.config_file_provider = f(self.config_file_provider);
        self.rebuild_chain();
        self
    }

    /// Add a credential provider to the front of the default chain.
    ///
    /// This allows adding a high-priority credential source that will be tried
    /// before all other providers in the default chain.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_oracle::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new("user", "tenancy", "key_file", "fingerprint"));
    /// ```
    pub fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.chain = self.chain.push_front(provider);
        self
    }
}

#[async_trait]
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        self.chain.provide_credential(ctx).await
    }
}
