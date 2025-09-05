use crate::provide_credential::{
    AssumeRoleWithWebIdentityCredentialProvider, ECSCredentialProvider, EnvCredentialProvider,
    IMDSv2CredentialProvider, ProfileCredentialProvider,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::provide_credential::{ProcessCredentialProvider, SSOCredentialProvider};
use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};

/// DefaultCredentialProvider is a loader that will try to load credential via default chains.
///
/// Resolution order:
///
/// 1. Environment variables
/// 2. Shared config (`~/.aws/config`, `~/.aws/credentials`)
/// 3. SSO credentials
/// 4. Web Identity Tokens
/// 5. Process credentials
/// 6. ECS (IAM Roles for Tasks) & Container credentials
/// 7. EC2 IMDSv2
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    chain: ProvideCredentialChain<Credential>,
    env_provider: EnvCredentialProvider,
    profile_provider: ProfileCredentialProvider,
    #[cfg(not(target_arch = "wasm32"))]
    sso_provider: SSOCredentialProvider,
    assume_role_provider: AssumeRoleWithWebIdentityCredentialProvider,
    #[cfg(not(target_arch = "wasm32"))]
    process_provider: ProcessCredentialProvider,
    ecs_provider: ECSCredentialProvider,
    imds_provider: IMDSv2CredentialProvider,
}

impl Default for DefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCredentialProvider {
    /// Create a new `DefaultCredentialProvider` instance.
    pub fn new() -> Self {
        let env_provider = EnvCredentialProvider::new();
        let profile_provider = ProfileCredentialProvider::new();
        #[cfg(not(target_arch = "wasm32"))]
        let sso_provider = SSOCredentialProvider::new();
        let assume_role_provider = AssumeRoleWithWebIdentityCredentialProvider::new();
        #[cfg(not(target_arch = "wasm32"))]
        let process_provider = ProcessCredentialProvider::new();
        let ecs_provider = ECSCredentialProvider::new();
        let imds_provider = IMDSv2CredentialProvider::new();

        let mut provider = Self {
            chain: ProvideCredentialChain::new(),
            env_provider,
            profile_provider,
            #[cfg(not(target_arch = "wasm32"))]
            sso_provider,
            assume_role_provider,
            #[cfg(not(target_arch = "wasm32"))]
            process_provider,
            ecs_provider,
            imds_provider,
        };

        provider.rebuild_chain();
        provider
    }

    /// Rebuild the internal chain based on current provider configurations.
    fn rebuild_chain(&mut self) {
        let mut chain = ProvideCredentialChain::new()
            .push(self.env_provider.clone())
            .push(self.profile_provider.clone());

        #[cfg(not(target_arch = "wasm32"))]
        {
            chain = chain.push(self.sso_provider.clone());
        }

        chain = chain.push(self.assume_role_provider.clone());

        #[cfg(not(target_arch = "wasm32"))]
        {
            chain = chain.push(self.process_provider.clone());
        }

        chain = chain
            .push(self.ecs_provider.clone())
            .push(self.imds_provider.clone());

        self.chain = chain;
    }

    /// Create with a custom credential chain.
    pub fn with_chain(chain: ProvideCredentialChain<Credential>) -> Self {
        // When using custom chain, we don't have individual providers
        // This maintains backward compatibility
        let env_provider = EnvCredentialProvider::new();
        let profile_provider = ProfileCredentialProvider::new();
        #[cfg(not(target_arch = "wasm32"))]
        let sso_provider = SSOCredentialProvider::new();
        let assume_role_provider = AssumeRoleWithWebIdentityCredentialProvider::new();
        #[cfg(not(target_arch = "wasm32"))]
        let process_provider = ProcessCredentialProvider::new();
        let ecs_provider = ECSCredentialProvider::new();
        let imds_provider = IMDSv2CredentialProvider::new();

        Self {
            chain,
            env_provider,
            profile_provider,
            #[cfg(not(target_arch = "wasm32"))]
            sso_provider,
            assume_role_provider,
            #[cfg(not(target_arch = "wasm32"))]
            process_provider,
            ecs_provider,
            imds_provider,
        }
    }

    /// Add a credential provider to the front of the default chain.
    ///
    /// This allows adding a high-priority credential source that will be tried
    /// before all other providers in the default chain.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_aws_v4::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new("access_key_id", "secret_access_key"));
    /// ```
    pub fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.chain = self.chain.push_front(provider);
        self
    }

    /// Configure the IMDSv2 credential provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_aws_v4::DefaultCredentialProvider;
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .configure_imds(|p| p.with_disabled(true));
    /// ```
    pub fn configure_imds<F>(mut self, f: F) -> Self
    where
        F: FnOnce(IMDSv2CredentialProvider) -> IMDSv2CredentialProvider,
    {
        self.imds_provider = f(self.imds_provider);
        self.rebuild_chain();
        self
    }

    /// Configure the profile credential provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_aws_v4::DefaultCredentialProvider;
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .configure_profile(|p| p.with_profile("development"));
    /// ```
    pub fn configure_profile<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ProfileCredentialProvider) -> ProfileCredentialProvider,
    {
        self.profile_provider = f(self.profile_provider);
        self.rebuild_chain();
        self
    }

    /// Configure the SSO credential provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_aws_v4::DefaultCredentialProvider;
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .configure_sso(|p| p.with_endpoint("https://sso.internal"));
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn configure_sso<F>(mut self, f: F) -> Self
    where
        F: FnOnce(SSOCredentialProvider) -> SSOCredentialProvider,
    {
        self.sso_provider = f(self.sso_provider);
        self.rebuild_chain();
        self
    }

    /// Configure the assume role with web identity credential provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_aws_v4::DefaultCredentialProvider;
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .configure_assume_role(|p| p.with_disabled(true));
    /// ```
    pub fn configure_assume_role<F>(mut self, f: F) -> Self
    where
        F: FnOnce(
            AssumeRoleWithWebIdentityCredentialProvider,
        ) -> AssumeRoleWithWebIdentityCredentialProvider,
    {
        self.assume_role_provider = f(self.assume_role_provider);
        self.rebuild_chain();
        self
    }

    /// Configure the process credential provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_aws_v4::DefaultCredentialProvider;
    /// use std::time::Duration;
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .configure_process(|p| p.with_timeout(Duration::from_secs(30)));
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn configure_process<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ProcessCredentialProvider) -> ProcessCredentialProvider,
    {
        self.process_provider = f(self.process_provider);
        self.rebuild_chain();
        self
    }

    /// Configure the ECS credential provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_aws_v4::DefaultCredentialProvider;
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .configure_ecs(|p| p.with_endpoint("http://ecs.internal"));
    /// ```
    pub fn configure_ecs<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ECSCredentialProvider) -> ECSCredentialProvider,
    {
        self.ecs_provider = f(self.ecs_provider);
        self.rebuild_chain();
        self
    }
}

#[async_trait]
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        self.chain.provide_credential(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        AWS_ACCESS_KEY_ID, AWS_CONFIG_FILE, AWS_SECRET_ACCESS_KEY, AWS_SHARED_CREDENTIALS_FILE,
    };
    use reqsign_core::{OsEnv, StaticEnv};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;
    use std::env;

    #[tokio::test]
    async fn test_credential_env_loader_without_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        let l = DefaultCredentialProvider::new();
        let x = l.provide_credential(&ctx).await.expect("load must succeed");
        assert!(x.is_none());
    }

    #[tokio::test]
    async fn test_credential_env_loader_with_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
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

        let l = DefaultCredentialProvider::new();
        let x = l.provide_credential(&ctx).await.expect("load must succeed");

        let x = x.expect("must load succeed");
        assert_eq!("access_key_id", x.access_key_id);
        assert_eq!("secret_access_key", x.secret_access_key);
    }

    #[tokio::test]
    async fn test_credential_profile_loader_from_config() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
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

        let l = DefaultCredentialProvider::new();
        let x = l.provide_credential(&ctx).await.unwrap().unwrap();
        assert_eq!("config_access_key_id", x.access_key_id);
        assert_eq!("config_secret_access_key", x.secret_access_key);
    }

    #[tokio::test]
    async fn test_credential_profile_loader_from_shared() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
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

        let l = DefaultCredentialProvider::new();
        let x = l.provide_credential(&ctx).await.unwrap().unwrap();
        assert_eq!("shared_access_key_id", x.access_key_id);
        assert_eq!("shared_secret_access_key", x.secret_access_key);
    }

    #[tokio::test]
    async fn test_default_credential_provider_prepend() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from_iter([
                // Set environment variables that would normally be loaded
                (AWS_ACCESS_KEY_ID.to_string(), "env_access_key".to_string()),
                (
                    AWS_SECRET_ACCESS_KEY.to_string(),
                    "env_secret_key".to_string(),
                ),
            ]),
        });

        // Create a static provider with different credentials
        let static_provider =
            crate::StaticCredentialProvider::new("static_access_key", "static_secret_key");

        // Create default provider and push_front the static provider
        let provider = DefaultCredentialProvider::new().push_front(static_provider);

        // The static provider should take precedence over environment variables
        let cred = provider
            .provide_credential(&ctx)
            .await
            .expect("load must succeed")
            .expect("credential must exist");

        assert_eq!("static_access_key", cred.access_key_id);
        assert_eq!("static_secret_key", cred.secret_access_key);
    }

    #[tokio::test]
    async fn test_default_credential_provider_configure_imds() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        // Configure IMDS to be disabled
        let provider = DefaultCredentialProvider::new().configure_imds(|p| p.with_disabled(true));

        // Even though IMDS is the last provider, it should return None when disabled
        let cred = provider
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");
        assert!(cred.is_none());
    }

    #[tokio::test]
    async fn test_default_credential_provider_configure_profile() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        });

        // Configure profile provider with custom files
        let provider = DefaultCredentialProvider::new().configure_profile(|p| {
            p.with_config_file(format!(
                "{}/testdata/default_config",
                env::current_dir()
                    .expect("current_dir must exist")
                    .to_string_lossy()
            ))
        });

        // Should load from the custom config
        let cred = provider
            .provide_credential(&ctx)
            .await
            .expect("load must succeed");
        // The testdata/default_config has credentials
        let cred = cred.expect("credential should exist");
        assert_eq!("config_access_key_id", cred.access_key_id);
        assert_eq!("config_secret_access_key", cred.secret_access_key);
    }

    /// AWS_SHARED_CREDENTIALS_FILE should be taken first.
    #[tokio::test]
    async fn test_credential_profile_loader_from_both() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
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

        let l = DefaultCredentialProvider::new();
        let x = l
            .provide_credential(&ctx)
            .await
            .expect("load must success")
            .unwrap();
        assert_eq!("shared_access_key_id", x.access_key_id);
        assert_eq!("shared_secret_access_key", x.secret_access_key);
    }
}
