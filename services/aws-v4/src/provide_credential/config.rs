use crate::{Config, Credential};
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, Result};
use std::sync::Arc;

/// TODO: we should support refresh from config file.
#[derive(Debug)]
pub struct ConfigCredentialProvider {
    config: Arc<Config>,
}

impl ConfigCredentialProvider {
    /// Create a new `ConfigCredentialProvider` instance.
    pub fn new(cfg: Arc<Config>) -> Self {
        Self { config: cfg }
    }
}

#[async_trait]
impl ProvideCredential for ConfigCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(
        &self,
        _: &Context,
    ) -> Result<Option<Self::Credential>> {
        let (Some(ak), Some(sk)) = (&self.config.access_key_id, &self.config.secret_access_key)
        else {
            return Ok(None);
        };

        Ok(Some(Credential {
            access_key_id: ak.clone(),
            secret_access_key: sk.clone(),
            session_token: self.config.session_token.clone(),
            expires_in: None,
        }))
    }
}
