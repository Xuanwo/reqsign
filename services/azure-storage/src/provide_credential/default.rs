#[cfg(not(target_arch = "wasm32"))]
use crate::provide_credential::{AzureCliCredentialProvider, ClientCertificateCredentialProvider};
use crate::provide_credential::{
    AzurePipelinesCredentialProvider, ClientSecretCredentialProvider, EnvCredentialProvider,
    ImdsCredentialProvider, WorkloadIdentityCredentialProvider,
};
use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};

/// Default loader that tries multiple credential sources in order.
///
/// The default loader attempts to load credentials from the following sources in order:
/// 1. Environment variables (account key, SAS token)
/// 2. Azure CLI (local development)
/// 3. Client certificate (service principal with certificate)
/// 4. Client secret (service principal)
/// 5. Azure Pipelines (workload identity)
/// 6. Workload identity (federated credentials)
/// 7. IMDS (Azure VM managed identity)
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    chain: ProvideCredentialChain<Credential>,
}

impl Default for DefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCredentialProvider {
    /// Create a builder to configure the default credential chain.
    pub fn builder() -> DefaultCredentialProviderBuilder {
        DefaultCredentialProviderBuilder::default()
    }

    /// Create a new default loader.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create with a custom credential chain.
    pub fn with_chain(chain: ProvideCredentialChain<Credential>) -> Self {
        Self { chain }
    }

    /// Add a credential provider to the front of the default chain.
    ///
    /// This allows adding a high-priority credential source that will be tried
    /// before all other providers in the default chain.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_azure_storage::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new_shared_key("account_name", "account_key"));
    /// ```
    pub fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.chain = self.chain.push_front(provider);
        self
    }
}

#[derive(Default)]
pub struct DefaultCredentialProviderBuilder {
    env: Option<EnvCredentialProvider>,
    #[cfg(not(target_arch = "wasm32"))]
    azure_cli: Option<AzureCliCredentialProvider>,
    #[cfg(not(target_arch = "wasm32"))]
    client_certificate: Option<ClientCertificateCredentialProvider>,
    client_secret: Option<ClientSecretCredentialProvider>,
    azure_pipelines: Option<AzurePipelinesCredentialProvider>,
    workload_identity: Option<WorkloadIdentityCredentialProvider>,
    imds: Option<ImdsCredentialProvider>,
}

impl DefaultCredentialProviderBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn configure_env<F>(mut self, f: F) -> Self
    where
        F: FnOnce(EnvCredentialProvider) -> EnvCredentialProvider,
    {
        let p = self.env.take().unwrap_or_default();
        self.env = Some(f(p));
        self
    }

    pub fn disable_env(mut self, disable: bool) -> Self {
        if disable {
            self.env = None;
        } else if self.env.is_none() {
            self.env = Some(EnvCredentialProvider::new());
        }
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn configure_azure_cli<F>(mut self, f: F) -> Self
    where
        F: FnOnce(AzureCliCredentialProvider) -> AzureCliCredentialProvider,
    {
        let p = self.azure_cli.take().unwrap_or_default();
        self.azure_cli = Some(f(p));
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn disable_azure_cli(mut self, disable: bool) -> Self {
        if disable {
            self.azure_cli = None;
        } else if self.azure_cli.is_none() {
            self.azure_cli = Some(AzureCliCredentialProvider::new());
        }
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn configure_client_certificate<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ClientCertificateCredentialProvider) -> ClientCertificateCredentialProvider,
    {
        let p = self.client_certificate.take().unwrap_or_default();
        self.client_certificate = Some(f(p));
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn disable_client_certificate(mut self, disable: bool) -> Self {
        if disable {
            self.client_certificate = None;
        } else if self.client_certificate.is_none() {
            self.client_certificate = Some(ClientCertificateCredentialProvider::new());
        }
        self
    }

    pub fn configure_client_secret<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ClientSecretCredentialProvider) -> ClientSecretCredentialProvider,
    {
        let p = self.client_secret.take().unwrap_or_default();
        self.client_secret = Some(f(p));
        self
    }

    pub fn disable_client_secret(mut self, disable: bool) -> Self {
        if disable {
            self.client_secret = None;
        } else if self.client_secret.is_none() {
            self.client_secret = Some(ClientSecretCredentialProvider::new());
        }
        self
    }

    pub fn configure_azure_pipelines<F>(mut self, f: F) -> Self
    where
        F: FnOnce(AzurePipelinesCredentialProvider) -> AzurePipelinesCredentialProvider,
    {
        let p = self.azure_pipelines.take().unwrap_or_default();
        self.azure_pipelines = Some(f(p));
        self
    }

    pub fn disable_azure_pipelines(mut self, disable: bool) -> Self {
        if disable {
            self.azure_pipelines = None;
        } else if self.azure_pipelines.is_none() {
            self.azure_pipelines = Some(AzurePipelinesCredentialProvider::new());
        }
        self
    }

    pub fn configure_workload_identity<F>(mut self, f: F) -> Self
    where
        F: FnOnce(WorkloadIdentityCredentialProvider) -> WorkloadIdentityCredentialProvider,
    {
        let p = self.workload_identity.take().unwrap_or_default();
        self.workload_identity = Some(f(p));
        self
    }

    pub fn disable_workload_identity(mut self, disable: bool) -> Self {
        if disable {
            self.workload_identity = None;
        } else if self.workload_identity.is_none() {
            self.workload_identity = Some(WorkloadIdentityCredentialProvider::new());
        }
        self
    }

    pub fn configure_imds<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ImdsCredentialProvider) -> ImdsCredentialProvider,
    {
        let p = self.imds.take().unwrap_or_default();
        self.imds = Some(f(p));
        self
    }

    pub fn disable_imds(mut self, disable: bool) -> Self {
        if disable {
            self.imds = None;
        } else if self.imds.is_none() {
            self.imds = Some(ImdsCredentialProvider::new());
        }
        self
    }

    pub fn build(self) -> DefaultCredentialProvider {
        let mut chain = ProvideCredentialChain::new();

        if let Some(p) = self.env {
            chain = chain.push(p);
        } else {
            chain = chain.push(EnvCredentialProvider::new());
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Some(p) = self.azure_cli {
                chain = chain.push(p);
            } else {
                chain = chain.push(AzureCliCredentialProvider::new());
            }

            if let Some(p) = self.client_certificate {
                chain = chain.push(p);
            } else {
                chain = chain.push(ClientCertificateCredentialProvider::new());
            }
        }

        if let Some(p) = self.client_secret {
            chain = chain.push(p);
        } else {
            chain = chain.push(ClientSecretCredentialProvider::new());
        }

        if let Some(p) = self.azure_pipelines {
            chain = chain.push(p);
        } else {
            chain = chain.push(AzurePipelinesCredentialProvider::new());
        }

        if let Some(p) = self.workload_identity {
            chain = chain.push(p);
        } else {
            chain = chain.push(WorkloadIdentityCredentialProvider::new());
        }

        if let Some(p) = self.imds {
            chain = chain.push(p);
        } else {
            chain = chain.push(ImdsCredentialProvider::new());
        }

        DefaultCredentialProvider::with_chain(chain)
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
    use reqsign_core::StaticEnv;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_config_loader_priority() {
        let env = StaticEnv {
            home_dir: None,
            envs: HashMap::from([
                (
                    "AZBLOB_ACCOUNT_NAME".to_string(),
                    "test_account".to_string(),
                ),
                ("AZBLOB_ACCOUNT_KEY".to_string(), "dGVzdF9rZXk=".to_string()),
            ]),
        };

        // Create a mock context - in real usage Context would be created with proper FileRead and HttpSend
        let ctx = reqsign_core::Context::new()
            .with_file_read(MockFileRead)
            .with_http_send(MockHttpSend)
            .with_env(env);

        let loader = DefaultCredentialProvider::new();

        let cred = loader.provide_credential(&ctx).await.unwrap().unwrap();
        match cred {
            crate::Credential::SharedKey {
                account_name,
                account_key,
            } => {
                assert_eq!(account_name, "test_account");
                assert_eq!(account_key, "dGVzdF9rZXk=");
            }
            _ => panic!("Expected SharedKey credential"),
        }
    }

    #[tokio::test]
    async fn test_sas_token_priority() {
        let env = StaticEnv {
            home_dir: None,
            envs: HashMap::from([(
                "AZURE_STORAGE_SAS_TOKEN".to_string(),
                "sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx".to_string(),
            )]),
        };

        let ctx = reqsign_core::Context::new()
            .with_file_read(MockFileRead)
            .with_http_send(MockHttpSend)
            .with_env(env);

        let loader = DefaultCredentialProvider::new();

        let cred = loader.provide_credential(&ctx).await.unwrap().unwrap();
        match cred {
            crate::Credential::SasToken { token } => {
                assert_eq!(token, "sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx");
            }
            _ => panic!("Expected SasToken credential"),
        }
    }

    // Mock implementations for testing
    #[derive(Debug)]
    struct MockFileRead;

    #[async_trait]
    impl reqsign_core::FileRead for MockFileRead {
        async fn file_read(&self, _path: &str) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug)]
    struct MockHttpSend;

    #[async_trait]
    impl reqsign_core::HttpSend for MockHttpSend {
        async fn http_send(
            &self,
            _req: http::Request<bytes::Bytes>,
        ) -> Result<http::Response<bytes::Bytes>> {
            Ok(http::Response::new(bytes::Bytes::new()))
        }
    }
}
