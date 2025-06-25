use async_trait::async_trait;
use reqsign_core::Result;
use reqsign_core::{Context, ProvideCredential};

use crate::Credential;

/// ConfigCredentialProvider will load credential from config.
///
/// # Deprecated
///
/// This provider is deprecated and will be removed in a future version.
/// Use `StaticCredentialProvider` for static credentials or `EnvCredentialProvider`
/// for environment-based credentials instead.
#[deprecated(
    since = "0.1.0",
    note = "Use StaticCredentialProvider or EnvCredentialProvider instead"
)]
#[derive(Debug)]
pub struct ConfigCredentialProvider;

#[allow(deprecated)]
impl ConfigCredentialProvider {
    /// Create a new ConfigCredentialProvider - this is a no-op and deprecated
    pub fn new(_: std::sync::Arc<()>) -> Self {
        Self
    }
}

#[async_trait]
#[allow(deprecated)]
impl ProvideCredential for ConfigCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        // Always return None since Config is removed
        Ok(None)
    }
}
