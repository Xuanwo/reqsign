use crate::{Config, Credential};
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain};
use std::sync::Arc;

/// Default loader for Tencent COS.
///
/// This loader will try to load credentials in the following order:
/// 1. From static configuration
/// 2. From AssumeRoleWithWebIdentity
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    chain: ProvideCredentialChain<Credential>,
}

impl DefaultCredentialProvider {
    /// Create a new DefaultCredentialProvider
    pub fn new(config: Config) -> Self {
        let chain = ProvideCredentialChain::new()
            .push(super::ConfigCredentialProvider::new(Arc::new(
                config.clone(),
            )))
            .push(super::AssumeRoleWithWebIdentityCredentialProvider::new(
                Arc::new(config),
            ));

        Self { chain }
    }
}

#[async_trait]
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Self::Credential>> {
        self.chain.provide_credential(ctx).await
    }
}
