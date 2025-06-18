use anyhow::Result;
use log::debug;

use reqsign_core::{Context, ProvideCredential};

use crate::config::Config;
use crate::constants::GOOGLE_APPLICATION_CREDENTIALS;
use crate::credential::{Credential, RawCredential};

/// ConfigLoader loads service account credentials from configuration.
/// 
/// This loader only returns service account credentials. Other credential types
/// (external account, impersonated service account) should be loaded by DefaultLoader.
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    config: Config,
}

impl ConfigLoader {
    /// Create a new ConfigLoader.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    async fn load_from_path(&self, ctx: &Context, path: &str) -> Result<Option<RawCredential>> {
        let content = ctx.file_read(path).await.map_err(|err| {
            debug!("load credential from path {path} failed: {err:?}");
            err
        })?;

        let cred = RawCredential::from_slice(&content).map_err(|err| {
            debug!("parse credential from path {path} failed: {err:?}");
            err
        })?;

        Ok(Some(cred))
    }

    async fn load_from_content(&self, content: &str) -> Result<Option<RawCredential>> {
        let cred = RawCredential::from_base64(content).map_err(|err| {
            debug!("parse credential from content failed: {err:?}");
            err
        })?;

        Ok(Some(cred))
    }

    async fn load_from_env(&self, ctx: &Context) -> Result<Option<RawCredential>> {
        if self.config.disable_env {
            return Ok(None);
        }

        let Some(path) = ctx.env_var(GOOGLE_APPLICATION_CREDENTIALS) else {
            return Ok(None);
        };

        self.load_from_path(ctx, &path).await
    }

    async fn load_from_well_known_location(&self, ctx: &Context) -> Result<Option<RawCredential>> {
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
impl ProvideCredential for ConfigLoader {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let raw_cred = if let Some(content) = &self.config.credential_content {
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

        // Convert RawCredential to Credential
        // ConfigLoader only returns service account credentials
        Ok(raw_cred.and_then(|raw| {
            raw.service_account
                .map(Credential::with_service_account)
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

        let loader = ConfigLoader::new(config);
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

        let loader = ConfigLoader::new(config);
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

        let loader = ConfigLoader::new(config);
        let cred = loader
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");
        // ConfigLoader only returns service accounts, so external account should return None
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

        let loader = ConfigLoader::new(config);
        let cred = loader
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");
        // ConfigLoader only returns service accounts, so impersonated service account should return None
        assert!(cred.is_none());
    }
}
