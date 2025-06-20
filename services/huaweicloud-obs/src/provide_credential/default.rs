use reqsign_core::Result;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain};
use std::sync::Arc;

use crate::config::Config;
use crate::credential::Credential;
use crate::provide_credential::ConfigCredentialProvider;

/// DefaultCredentialProvider will try to load credential from different sources.
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    chain: ProvideCredentialChain<Credential>,
}

impl DefaultCredentialProvider {
    /// Create a new DefaultCredentialProvider
    pub fn new(config: Config) -> Self {
        let chain =
            ProvideCredentialChain::new().push(ConfigCredentialProvider::new(Arc::new(config)));

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
