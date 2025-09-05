use log::debug;

use reqsign_core::{Context, ProvideCredential, Result};

use crate::constants::{DEFAULT_SCOPE, GOOGLE_APPLICATION_CREDENTIALS, GOOGLE_SCOPE};
use crate::credential::{Credential, CredentialFile};

use super::{
    authorized_user::AuthorizedUserCredentialProvider,
    external_account::ExternalAccountCredentialProvider,
    impersonated_service_account::ImpersonatedServiceAccountCredentialProvider,
    vm_metadata::VmMetadataCredentialProvider,
};

/// DefaultCredentialProvider tries to load credentials from multiple sources in order.
///
/// It follows the Google Application Default Credentials (ADC) strategy:
/// 1. GOOGLE_APPLICATION_CREDENTIALS environment variable
/// 2. gcloud credential file (~/.config/gcloud/application_default_credentials.json)
/// 3. Metadata server (for GCE/Cloud Functions/App Engine)
///
/// The provider automatically handles all credential types including:
/// - Service Account
/// - External Account (Workload Identity)
/// - Impersonated Service Account
/// - Authorized User (OAuth2)
#[derive(Debug, Clone)]
pub struct DefaultCredentialProvider {
    scope: Option<String>,
    vm_metadata_disabled: Option<bool>,
    vm_metadata_endpoint: Option<String>,
    skip_env: Option<bool>,
    skip_well_known: Option<bool>,
}

impl Default for DefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCredentialProvider {
    /// Create a new DefaultCredentialProvider.
    pub fn new() -> Self {
        Self {
            scope: None,
            vm_metadata_disabled: None,
            vm_metadata_endpoint: None,
            skip_env: None,
            skip_well_known: None,
        }
    }

    /// Set the OAuth2 scope.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Configure VM metadata provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_google::DefaultCredentialProvider;
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .configure_vm_metadata(|p| p.with_disabled(true));
    /// ```
    pub fn configure_vm_metadata<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut Self) -> &mut Self,
    {
        f(&mut self);
        self
    }

    /// Set whether VM metadata is disabled.
    pub fn with_vm_metadata_disabled(mut self, disabled: bool) -> Self {
        self.vm_metadata_disabled = Some(disabled);
        self
    }

    /// Set VM metadata endpoint.
    pub fn with_vm_metadata_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.vm_metadata_endpoint = Some(endpoint.into());
        self
    }

    /// Skip loading from GOOGLE_APPLICATION_CREDENTIALS environment variable.
    pub fn skip_env_credentials(mut self, skip: bool) -> Self {
        self.skip_env = Some(skip);
        self
    }

    /// Skip loading from well-known location.
    pub fn skip_well_known_location(mut self, skip: bool) -> Self {
        self.skip_well_known = Some(skip);
        self
    }

    /// Add a credential provider to the front of the default chain.
    ///
    /// Note: Google's DefaultCredentialProvider doesn't use ProvideCredentialChain internally,
    /// but this method is provided for API consistency with other providers.
    /// The custom provider will be tried first before the default ADC flow.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_google::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new("service_account_json"));
    /// ```
    pub fn push_front(
        self,
        _provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        // Note: This implementation would need refactoring to support chain-based approach
        // For now, we keep the method for API consistency
        log::warn!("push_front is not yet implemented for Google DefaultCredentialProvider");
        self
    }

    /// Try to load credentials from GOOGLE_APPLICATION_CREDENTIALS environment variable.
    async fn try_env_credentials(&self, ctx: &Context) -> Result<Option<Credential>> {
        if self.skip_env.unwrap_or(false) {
            return Ok(None);
        }

        let Some(path) = ctx.env_var(GOOGLE_APPLICATION_CREDENTIALS) else {
            return Ok(None);
        };

        debug!("trying to load credential from env GOOGLE_APPLICATION_CREDENTIALS: {path}");
        self.load_credential_from_path(ctx, &path).await
    }

    /// Try to load credentials from gcloud default location.
    async fn try_well_known_location(&self, ctx: &Context) -> Result<Option<Credential>> {
        if self.skip_well_known.unwrap_or(false) {
            return Ok(None);
        }

        let config_dir = if let Some(v) = ctx.env_var("APPDATA") {
            v
        } else if let Some(v) = ctx.env_var("XDG_CONFIG_HOME") {
            v
        } else if let Some(v) = ctx.env_var("HOME") {
            format!("{v}/.config")
        } else {
            return Ok(None);
        };

        let path = format!("{config_dir}/gcloud/application_default_credentials.json");
        debug!("trying to load credential from well-known location: {path}");

        match self.load_credential_from_path(ctx, &path).await {
            Ok(cred) => Ok(cred),
            Err(_) => Ok(None), // Ignore errors for well-known location
        }
    }

    /// Try to load credentials from metadata server.
    async fn try_metadata_server(&self, ctx: &Context) -> Result<Option<Credential>> {
        if self.vm_metadata_disabled.unwrap_or(false) {
            return Ok(None);
        }

        debug!("trying to load credential from metadata server");

        let mut provider = match &self.scope {
            Some(scope) => VmMetadataCredentialProvider::new().with_scope(scope),
            None => VmMetadataCredentialProvider::new(),
        };

        if let Some(endpoint) = &self.vm_metadata_endpoint {
            provider = provider.with_endpoint(endpoint);
        }

        provider.provide_credential(ctx).await
    }

    /// Load credential from a file path and handle all credential types.
    async fn load_credential_from_path(
        &self,
        ctx: &Context,
        path: &str,
    ) -> Result<Option<Credential>> {
        let content = ctx.file_read(path).await.map_err(|err| {
            debug!("failed to read credential file {path}: {err:?}");
            err
        })?;

        let cred_file = CredentialFile::from_slice(&content).map_err(|err| {
            debug!("failed to parse credential file {path}: {err:?}");
            err
        })?;

        // Get scope from instance, environment, or use default
        let scope = self
            .scope
            .clone()
            .or_else(|| ctx.env_var(GOOGLE_SCOPE))
            .unwrap_or_else(|| DEFAULT_SCOPE.to_string());

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

#[async_trait::async_trait]
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // 1. Try environment variable
        if let Some(cred) = self.try_env_credentials(ctx).await? {
            return Ok(Some(cred));
        }

        // 2. Try well-known location
        if let Some(cred) = self.try_well_known_location(ctx).await? {
            return Ok(Some(cred));
        }

        // 3. Try metadata server
        if let Some(cred) = self.try_metadata_server(ctx).await? {
            return Ok(Some(cred));
        }

        debug!("no valid credential source found");
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::{Context, StaticEnv};
    use std::collections::HashMap;
    use std::env;

    #[tokio::test]
    async fn test_default_provider_env() {
        let envs = HashMap::from([(
            GOOGLE_APPLICATION_CREDENTIALS.to_string(),
            format!(
                "{}/testdata/test_credential.json",
                env::current_dir()
                    .expect("current_dir must exist")
                    .to_string_lossy()
            ),
        )]);

        let ctx = Context::new()
            .with_file_read(reqsign_file_read_tokio::TokioFileRead)
            .with_http_send(reqsign_http_send_reqwest::ReqwestHttpSend::default())
            .with_env(StaticEnv {
                home_dir: None,
                envs,
            });

        let provider = DefaultCredentialProvider::new();
        let cred = provider
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");
        assert!(cred.is_some());

        let cred = cred.unwrap();
        assert!(cred.has_service_account());
        let sa = cred.service_account.as_ref().unwrap();
        assert_eq!("test-234@test.iam.gserviceaccount.com", &sa.client_email);
    }

    #[tokio::test]
    async fn test_default_provider_with_scope() {
        let provider = DefaultCredentialProvider::new()
            .with_scope("https://www.googleapis.com/auth/devstorage.read_only");

        // Even without valid credentials, this should not panic
        let ctx = Context::new()
            .with_file_read(reqsign_file_read_tokio::TokioFileRead)
            .with_http_send(reqsign_http_send_reqwest::ReqwestHttpSend::default());
        let _ = provider.provide_credential(&ctx).await;
    }
}
