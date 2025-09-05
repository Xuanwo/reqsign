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
    env_provider: EnvCredentialProvider,
    #[cfg(not(target_arch = "wasm32"))]
    azure_cli_provider: AzureCliCredentialProvider,
    #[cfg(not(target_arch = "wasm32"))]
    client_certificate_provider: ClientCertificateCredentialProvider,
    client_secret_provider: ClientSecretCredentialProvider,
    azure_pipelines_provider: AzurePipelinesCredentialProvider,
    workload_identity_provider: WorkloadIdentityCredentialProvider,
    imds_provider: ImdsCredentialProvider,
}

impl Default for DefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCredentialProvider {
    /// Create a new default loader.
    pub fn new() -> Self {
        let env_provider = EnvCredentialProvider::new();
        #[cfg(not(target_arch = "wasm32"))]
        let azure_cli_provider = AzureCliCredentialProvider::new();
        #[cfg(not(target_arch = "wasm32"))]
        let client_certificate_provider = ClientCertificateCredentialProvider::new();
        let client_secret_provider = ClientSecretCredentialProvider::new();
        let azure_pipelines_provider = AzurePipelinesCredentialProvider::new();
        let workload_identity_provider = WorkloadIdentityCredentialProvider::new();
        let imds_provider = ImdsCredentialProvider::new();

        let mut provider = Self {
            chain: ProvideCredentialChain::new(),
            env_provider,
            #[cfg(not(target_arch = "wasm32"))]
            azure_cli_provider,
            #[cfg(not(target_arch = "wasm32"))]
            client_certificate_provider,
            client_secret_provider,
            azure_pipelines_provider,
            workload_identity_provider,
            imds_provider,
        };

        provider.rebuild_chain();
        provider
    }

    /// Rebuild the internal chain based on current provider configurations.
    fn rebuild_chain(&mut self) {
        let mut chain = ProvideCredentialChain::new().push(self.env_provider.clone());

        #[cfg(not(target_arch = "wasm32"))]
        {
            chain = chain
                .push(self.azure_cli_provider.clone())
                .push(self.client_certificate_provider.clone());
        }

        chain = chain
            .push(self.client_secret_provider.clone())
            .push(self.azure_pipelines_provider.clone())
            .push(self.workload_identity_provider.clone())
            .push(self.imds_provider.clone());

        self.chain = chain;
    }

    /// Configure the IMDS credential provider.\n    ///\n    /// # Example\n    ///\n    /// ```no_run\n    /// use reqsign_azure_storage::DefaultCredentialProvider;\n    ///\n    /// let provider = DefaultCredentialProvider::new()\n    ///     .configure_imds(|p| p.with_disabled(true));\n    /// ```\n    pub fn configure_imds<F>(mut self, f: F) -> Self\n    where\n        F: FnOnce(ImdsCredentialProvider) -> ImdsCredentialProvider,\n    {\n        self.imds_provider = f(self.imds_provider);\n        self.rebuild_chain();\n        self\n    }\n\n    /// Configure the Azure CLI credential provider.\n    ///\n    /// # Example\n    ///\n    /// ```no_run\n    /// use reqsign_azure_storage::DefaultCredentialProvider;\n    ///\n    /// let provider = DefaultCredentialProvider::new()\n    ///     .configure_azure_cli(|p| p.with_disabled(true));\n    /// ```\n    #[cfg(not(target_arch = \"wasm32\"))]\n    pub fn configure_azure_cli<F>(mut self, f: F) -> Self\n    where\n        F: FnOnce(AzureCliCredentialProvider) -> AzureCliCredentialProvider,\n    {\n        self.azure_cli_provider = f(self.azure_cli_provider);\n        self.rebuild_chain();\n        self\n    }\n\n    /// Configure the client certificate credential provider.\n    ///\n    /// # Example\n    ///\n    /// ```no_run\n    /// use reqsign_azure_storage::DefaultCredentialProvider;\n    ///\n    /// let provider = DefaultCredentialProvider::new()\n    ///     .configure_client_certificate(|p| p.with_tenant_id(\"tenant\"));\n    /// ```\n    #[cfg(not(target_arch = \"wasm32\"))]\n    pub fn configure_client_certificate<F>(mut self, f: F) -> Self\n    where\n        F: FnOnce(ClientCertificateCredentialProvider) -> ClientCertificateCredentialProvider,\n    {\n        self.client_certificate_provider = f(self.client_certificate_provider);\n        self.rebuild_chain();\n        self\n    }\n\n    /// Configure the client secret credential provider.\n    ///\n    /// # Example\n    ///\n    /// ```no_run\n    /// use reqsign_azure_storage::DefaultCredentialProvider;\n    ///\n    /// let provider = DefaultCredentialProvider::new()\n    ///     .configure_client_secret(|p| p.with_tenant_id(\"tenant\"));\n    /// ```\n    pub fn configure_client_secret<F>(mut self, f: F) -> Self\n    where\n        F: FnOnce(ClientSecretCredentialProvider) -> ClientSecretCredentialProvider,\n    {\n        self.client_secret_provider = f(self.client_secret_provider);\n        self.rebuild_chain();\n        self\n    }\n\n    /// Configure the Azure Pipelines credential provider.\n    ///\n    /// # Example\n    ///\n    /// ```no_run\n    /// use reqsign_azure_storage::DefaultCredentialProvider;\n    ///\n    /// let provider = DefaultCredentialProvider::new()\n    ///     .configure_azure_pipelines(|p| p.with_disabled(true));\n    /// ```\n    pub fn configure_azure_pipelines<F>(mut self, f: F) -> Self\n    where\n        F: FnOnce(AzurePipelinesCredentialProvider) -> AzurePipelinesCredentialProvider,\n    {\n        self.azure_pipelines_provider = f(self.azure_pipelines_provider);\n        self.rebuild_chain();\n        self\n    }\n\n    /// Configure the workload identity credential provider.\n    ///\n    /// # Example\n    ///\n    /// ```no_run\n    /// use reqsign_azure_storage::DefaultCredentialProvider;\n    ///\n    /// let provider = DefaultCredentialProvider::new()\n    ///     .configure_workload_identity(|p| p.with_tenant_id(\"tenant\"));\n    /// ```\n    pub fn configure_workload_identity<F>(mut self, f: F) -> Self\n    where\n        F: FnOnce(WorkloadIdentityCredentialProvider) -> WorkloadIdentityCredentialProvider,\n    {\n        self.workload_identity_provider = f(self.workload_identity_provider);\n        self.rebuild_chain();\n        self\n    }\n\n    /// Add a credential provider to the front of the default chain.
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
