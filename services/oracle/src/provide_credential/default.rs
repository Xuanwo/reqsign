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
}

impl DefaultCredentialProvider {
    /// Create a new DefaultCredentialProvider
    pub fn new() -> Self {
        let chain = ProvideCredentialChain::new()
            .push(EnvCredentialProvider::new())
            .push(ConfigFileCredentialProvider::new());

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
    /// use reqsign_oracle::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new("tenancy", "user", "fingerprint", "private_key"));
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
