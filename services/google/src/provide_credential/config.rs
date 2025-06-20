use log::debug;

use reqsign_core::{Context, ProvideCredential};

use crate::config::Config;
use crate::constants::GOOGLE_APPLICATION_CREDENTIALS;
use crate::credential::{Credential, CredentialFile};

/// ConfigCredentialProvider loads service account credentials from configuration.
///
/// This loader only returns service account credentials. Other credential types
/// (external account, impersonated service account) should be loaded by DefaultCredentialProvider.
#[derive(Debug, Clone)]
pub struct ConfigCredentialProvider {
    config: Config,
}

impl ConfigCredentialProvider {
    /// Create a new ConfigCredentialProvider.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    async fn load_from_path(&self, ctx: &Context, path: &str) -> reqsign_core::Result<Option<CredentialFile>> {
        let content = ctx.file_read(path).await.map_err(|err| {
            debug!("load credential from path {path} failed: {err:?}");
            err
        })?;

        let cred = CredentialFile::from_slice(&content).map_err(|err| {
            debug!("parse credential from path {path} failed: {err:?}");
            err
        })?;

        Ok(Some(cred))
    }

    async fn load_from_content(&self, content: &str) -> reqsign_core::Result<Option<CredentialFile>> {
        let cred = CredentialFile::from_base64(content).map_err(|err| {
            debug!("parse credential from content failed: {err:?}");
            err
        })?;

        Ok(Some(cred))
    }

    async fn load_from_env(&self, ctx: &Context) -> reqsign_core::Result<Option<CredentialFile>> {
        if self.config.disable_env {
            return Ok(None);
        }

        let Some(path) = ctx.env_var(GOOGLE_APPLICATION_CREDENTIALS) else {
            return Ok(None);
        };

        self.load_from_path(ctx, &path).await
    }

    async fn load_from_well_known_location(&self, ctx: &Context) -> reqsign_core::Result<Option<CredentialFile>> {
        if self.config.disable_well_known_location {
            return Ok(None);
        }

        let config_dir = if let Some(v) = ctx.env_var("APPDATA") {
            v
        } else if let Some(v) = ctx.env_var("XDG_CONFIG_HOME") {
            v
        } else if let Some(v) = ctx.env_var("HOME") {
            format!("{v}/.config")
        } else {
            // User's env doesn't have a config dir.
            return Ok(None);
        };

        let path = format!("{config_dir}/gcloud/application_default_credentials.json");
        match self.load_from_path(ctx, &path).await {
            Ok(cred) => Ok(cred),
            Err(_) => Ok(None), // Ignore errors for well-known location
        }
    }
}

#[async_trait::async_trait]
impl ProvideCredential for ConfigCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Self::Credential>> {
        let cred_file = if let Some(content) = &self.config.credential_content {
            // Try content first
            self.load_from_content(content).await?
        } else if let Some(path) = &self.config.credential_path {
            // Try explicit path
            self.load_from_path(ctx, path).await?
        } else if let Ok(Some(cred)) = self.load_from_env(ctx).await {
            // Try environment variable
            Some(cred)
        } else if let Ok(Some(cred)) = self.load_from_well_known_location(ctx).await {
            // Try well-known location
            Some(cred)
        } else {
            None
        };

        // Convert CredentialFile to Credential
        // ConfigCredentialProvider only returns service account credentials
        Ok(cred_file.and_then(|file| match file {
            CredentialFile::ServiceAccount(sa) => Some(Credential::with_service_account(sa)),
            _ => None, // Other types are not supported by ConfigCredentialProvider
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::GOOGLE_APPLICATION_CREDENTIALS;
    use reqsign_core::{Context, StaticEnv};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;
    use std::env;

    fn test_context() -> Context {
        Context::new(TokioFileRead, ReqwestHttpSend::default())
    }

    fn test_context_with_env(envs: HashMap<String, String>) -> Context {
        Context::new(TokioFileRead, ReqwestHttpSend::default()).with_env(StaticEnv {
            home_dir: None,
            envs,
        })
    }

    #[tokio::test]
    async fn test_load_from_path() {
        let ctx = test_context();
        let config = Config::new().with_credential_path(format!(
            "{}/testdata/test_credential.json",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        ));

        let loader = ConfigCredentialProvider::new(config);
        let cred = loader
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
    async fn test_load_from_env() {
        let envs = HashMap::from([(
            GOOGLE_APPLICATION_CREDENTIALS.to_string(),
            format!(
                "{}/testdata/test_credential.json",
                env::current_dir()
                    .expect("current_dir must exist")
                    .to_string_lossy()
            ),
        )]);

        let ctx = test_context_with_env(envs);
        let config = Config::new();

        let loader = ConfigCredentialProvider::new(config);
        let cred = loader
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");
        assert!(cred.is_some());
    }

    #[tokio::test]
    async fn test_load_external_account() {
        let ctx = test_context();
        let config = Config::new().with_credential_path(format!(
            "{}/testdata/test_external_account.json",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        ));

        let loader = ConfigCredentialProvider::new(config);
        let cred = loader
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");
        // ConfigCredentialProvider only returns service accounts, so external account should return None
        assert!(cred.is_none());
    }

    #[tokio::test]
    async fn test_load_impersonated_service_account() {
        let ctx = test_context();
        let config = Config::new().with_credential_path(format!(
            "{}/testdata/test_impersonated_service_account.json",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        ));

        let loader = ConfigCredentialProvider::new(config);
        let cred = loader
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");
        // ConfigCredentialProvider only returns service accounts, so impersonated service account should return None
        assert!(cred.is_none());
    }
}
