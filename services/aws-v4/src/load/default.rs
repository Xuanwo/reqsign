use crate::load::config::ConfigLoader;
use crate::load::{AssumeRoleWithWebIdentityLoader, IMDSv2Loader};
use crate::{Config, Credential};
use async_trait::async_trait;
use reqsign_core::{Context, Load};
use std::sync::Arc;

/// DefaultLoader is a loader that will try to load credential via default chains.
///
/// Resolution order:
///
/// 1. Environment variables
/// 2. Shared config (`~/.aws/config`, `~/.aws/credentials`)
/// 3. Web Identity Tokens
/// 4. ECS (IAM Roles for Tasks) & General HTTP credentials (TODO)
/// 5. EC2 IMDSv2
#[derive(Debug)]
pub struct DefaultLoader {
    config_loader: ConfigLoader,
    assume_role_with_web_identity_loader: AssumeRoleWithWebIdentityLoader,
    imds_v2_loader: IMDSv2Loader,
}

impl DefaultLoader {
    /// Create a new `DefaultLoader` instance.
    pub fn new(config: Arc<Config>) -> Self {
        let config_loader = ConfigLoader::new(config.clone());
        let assume_role_with_web_identity_loader =
            AssumeRoleWithWebIdentityLoader::new(config.clone());
        let imds_v2_loader = IMDSv2Loader::new(config.clone());

        Self {
            config_loader,
            assume_role_with_web_identity_loader,
            imds_v2_loader,
        }
    }
}

#[async_trait]
impl Load for DefaultLoader {
    type Key = Credential;

    async fn load(&self, ctx: &Context) -> anyhow::Result<Option<Self::Key>> {
        if let Some(cred) = self.config_loader.load(ctx).await? {
            return Ok(Some(cred));
        }

        if let Some(cred) = self.assume_role_with_web_identity_loader.load(ctx).await? {
            return Ok(Some(cred));
        }

        if let Some(cred) = self.imds_v2_loader.load(ctx).await? {
            return Ok(Some(cred));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        AWS_ACCESS_KEY_ID, AWS_CONFIG_FILE, AWS_SECRET_ACCESS_KEY, AWS_SHARED_CREDENTIALS_FILE,
    };
    use reqsign_core::StaticEnv;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;
    use std::env;

    #[tokio::test]
    async fn test_credential_env_loader_without_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let cfg = Config {
            ec2_metadata_disabled: true,
            ..Default::default()
        };

        let l = DefaultLoader::new(Arc::new(cfg));
        let x = l.load(&ctx).await.expect("load must succeed");
        assert!(x.is_none());
    }

    #[tokio::test]
    async fn test_credential_env_loader_with_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (AWS_ACCESS_KEY_ID.to_string(), "access_key_id".to_string()),
                (
                    AWS_SECRET_ACCESS_KEY.to_string(),
                    "secret_access_key".to_string(),
                ),
            ]),
        });

        let l = DefaultLoader::new(Arc::new(Config::default().from_env(&ctx)));
        let x = l.load(&ctx).await.expect("load must succeed");

        let x = x.expect("must load succeed");
        assert_eq!("access_key_id", x.access_key_id);
        assert_eq!("secret_access_key", x.secret_access_key);
    }

    #[tokio::test]
    async fn test_credential_profile_loader_from_config() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (
                    AWS_CONFIG_FILE.to_string(),
                    format!(
                        "{}/testdata/default_config",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    ),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE.to_string(),
                    format!(
                        "{}/testdata/not_exist",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    ),
                ),
            ]),
        });

        let l = DefaultLoader::new(
            Config::default()
                .from_env(&ctx)
                .from_profile(&ctx)
                .await
                .into(),
        );
        let x = l.load(&ctx).await.unwrap().unwrap();
        assert_eq!("config_access_key_id", x.access_key_id);
        assert_eq!("config_secret_access_key", x.secret_access_key);
    }

    #[tokio::test]
    async fn test_credential_profile_loader_from_shared() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (
                    AWS_CONFIG_FILE.to_string(),
                    format!(
                        "{}/testdata/not_exist",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    ),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE.to_string(),
                    format!(
                        "{}/testdata/default_credential",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    ),
                ),
            ]),
        });

        let l = DefaultLoader::new(
            Config::default()
                .from_env(&ctx)
                .from_profile(&ctx)
                .await
                .into(),
        );
        let x = l.load(&ctx).await.unwrap().unwrap();
        assert_eq!("shared_access_key_id", x.access_key_id);
        assert_eq!("shared_secret_access_key", x.secret_access_key);
    }

    /// AWS_SHARED_CREDENTIALS_FILE should be taken first.
    #[tokio::test]
    async fn test_credential_profile_loader_from_both() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                (
                    AWS_CONFIG_FILE.to_string(),
                    format!(
                        "{}/testdata/default_config",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    ),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE.to_string(),
                    format!(
                        "{}/testdata/default_credential",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    ),
                ),
            ]),
        });

        let l = DefaultLoader::new(
            Config::default()
                .from_env(&ctx)
                .from_profile(&ctx)
                .await
                .into(),
        );
        let x = l.load(&ctx).await.expect("load must success").unwrap();
        assert_eq!("shared_access_key_id", x.access_key_id);
        assert_eq!("shared_secret_access_key", x.secret_access_key);
    }
}
