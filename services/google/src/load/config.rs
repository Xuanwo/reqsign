use anyhow::Result;
use log::debug;

use reqsign_core::{Context, Load};

use crate::config::Config;
use crate::constants::GOOGLE_APPLICATION_CREDENTIALS;
use crate::key::RawCredential;

/// ConfigLoader loads credentials from the configuration.
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

    async fn load_from_well_known_location(
        &self,
        ctx: &Context,
    ) -> Result<Option<RawCredential>> {
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
impl Load for ConfigLoader {
    type Key = RawCredential;

    async fn load(&self, ctx: &Context) -> Result<Option<Self::Key>> {
        // Try content first
        if let Some(content) = &self.config.credential_content {
            if let Ok(Some(cred)) = self.load_from_content(content).await {
                return Ok(Some(cred));
            }
        }

        // Try explicit path
        if let Some(path) = &self.config.credential_path {
            if let Ok(Some(cred)) = self.load_from_path(ctx, path).await {
                return Ok(Some(cred));
            }
        }

        // Try environment variable
        if let Ok(Some(cred)) = self.load_from_env(ctx).await {
            return Ok(Some(cred));
        }

        // Try well-known location
        if let Ok(Some(cred)) = self.load_from_well_known_location(ctx).await {
            return Ok(Some(cred));
        }

        Ok(None)
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
        let cred = loader.load(&ctx).await.expect("load must succeed");
        assert!(cred.is_some());
        
        let cred = cred.unwrap();
        assert!(cred.service_account.is_some());
        let sa = cred.service_account.unwrap();
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
        let cred = loader.load(&ctx).await.expect("load must succeed");
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
        let cred = loader.load(&ctx).await.expect("load must succeed");
        assert!(cred.is_some());
        
        let cred = cred.unwrap();
        assert!(cred.external_account.is_some());
        let ea = cred.external_account.unwrap();
        assert_eq!(
            "//iam.googleapis.com/projects/000000000000/locations/global/workloadIdentityPools/reqsign/providers/reqsign-provider",
            &ea.audience
        );
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
        let cred = loader.load(&ctx).await.expect("load must succeed");
        assert!(cred.is_some());
        
        let cred = cred.unwrap();
        assert!(cred.impersonated_service_account.is_some());
        let isa = cred.impersonated_service_account.unwrap();
        assert_eq!(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/example-01-iam@example-01.iam.gserviceaccount.com:generateAccessToken",
            &isa.service_account_impersonation_url
        );
    }
}