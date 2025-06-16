use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential};

/// Load credential from configuration.
#[derive(Debug, Default)]
pub struct ConfigLoader {
    account_name: Option<String>,
    account_key: Option<String>,
    sas_token: Option<String>,
}

impl ConfigLoader {
    /// Create a new config loader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set account name.
    pub fn with_account_name(mut self, account_name: impl Into<String>) -> Self {
        self.account_name = Some(account_name.into());
        self
    }

    /// Set account key.
    pub fn with_account_key(mut self, account_key: impl Into<String>) -> Self {
        self.account_key = Some(account_key.into());
        self
    }

    /// Set SAS token.
    pub fn with_sas_token(mut self, sas_token: impl Into<String>) -> Self {
        self.sas_token = Some(sas_token.into());
        self
    }
}

#[async_trait]
impl ProvideCredential for ConfigLoader {
    type Credential = Credential;

    async fn provide_credential(&self, _: &Context) -> anyhow::Result<Option<Self::Credential>> {
        // Check SAS token first
        if let Some(sas_token) = &self.sas_token {
            if !sas_token.is_empty() {
                return Ok(Some(Credential::with_sas_token(sas_token.clone())));
            }
        }

        // Check shared key
        if let (Some(account_name), Some(account_key)) = (&self.account_name, &self.account_key) {
            if !account_name.is_empty() && !account_key.is_empty() {
                return Ok(Some(Credential::with_shared_key(
                    account_name.clone(),
                    account_key.clone(),
                )));
            }
        }

        Ok(None)
    }
}
