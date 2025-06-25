use log::debug;

use reqsign_core::{Context, ProvideCredential, Result};

use crate::credential::{Credential, CredentialFile};

use super::{
    authorized_user::AuthorizedUserCredentialProvider,
    external_account::ExternalAccountCredentialProvider,
    impersonated_service_account::ImpersonatedServiceAccountCredentialProvider,
};

/// StaticCredentialProvider loads credentials from a JSON string provided at construction time.
#[derive(Debug, Clone)]
pub struct StaticCredentialProvider {
    content: String,
    scope: Option<String>,
}

impl StaticCredentialProvider {
    /// Create a new StaticCredentialProvider from JSON content.
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            scope: None,
        }
    }

    /// Set the OAuth2 scope.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }
}

#[async_trait::async_trait]
impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        debug!("loading credential from static content");

        let cred_file = CredentialFile::from_slice(self.content.as_bytes()).map_err(|err| {
            debug!("failed to parse credential from content: {err:?}");
            err
        })?;

        // Get scope from instance or environment
        let scope = self
            .scope
            .clone()
            .or_else(|| ctx.env_var(crate::constants::GOOGLE_SCOPE))
            .unwrap_or_else(|| crate::constants::DEFAULT_SCOPE.to_string());

        match cred_file {
            CredentialFile::ServiceAccount(sa) => {
                debug!("loaded service account credential");
                Ok(Some(Credential::with_service_account(sa)))
            }
            CredentialFile::ExternalAccount(ea) => {
                debug!("loaded external account credential, exchanging for token");
                let provider = ExternalAccountCredentialProvider::new(ea).with_scope(&scope);
                provider.provide_credential(ctx).await
            }
            CredentialFile::ImpersonatedServiceAccount(isa) => {
                debug!("loaded impersonated service account credential, exchanging for token");
                let provider =
                    ImpersonatedServiceAccountCredentialProvider::new(isa).with_scope(&scope);
                provider.provide_credential(ctx).await
            }
            CredentialFile::AuthorizedUser(au) => {
                debug!("loaded authorized user credential, exchanging for token");
                let provider = AuthorizedUserCredentialProvider::new(au);
                provider.provide_credential(ctx).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::Context;

    #[tokio::test]
    async fn test_static_service_account() {
        let content = r#"{
            "type": "service_account",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
            "client_email": "test@example.iam.gserviceaccount.com"
        }"#;

        let provider = StaticCredentialProvider::new(content);
        let ctx = Context::new(
            reqsign_file_read_tokio::TokioFileRead,
            reqsign_http_send_reqwest::ReqwestHttpSend::default(),
        );

        let result = provider.provide_credential(&ctx).await;
        assert!(result.is_ok());

        let cred = result.unwrap();
        assert!(cred.is_some());

        let cred = cred.unwrap();
        assert!(cred.has_service_account());
    }
}
