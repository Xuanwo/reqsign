use crate::load::{ClientSecretLoader, ConfigLoader, ImdsLoader, WorkloadIdentityLoader};
use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, Key, ProvideCredential};

/// Default loader that tries multiple credential sources in order.
///
/// The default loader attempts to load credentials from the following sources in order:
/// 1. Configuration (account key, SAS token)
/// 2. Client secret (service principal)
/// 3. Workload identity (federated credentials)
/// 4. IMDS (Azure VM managed identity)
#[derive(Debug, Default)]
pub struct DefaultLoader {
    config_loader: ConfigLoader,
    client_secret_loader: ClientSecretLoader,
    workload_identity_loader: WorkloadIdentityLoader,
    imds_loader: ImdsLoader,
}

impl DefaultLoader {
    /// Create a new default loader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set account name and key for shared key authentication.
    pub fn with_account_key(
        mut self,
        account_name: impl Into<String>,
        account_key: impl Into<String>,
    ) -> Self {
        self.config_loader = self
            .config_loader
            .with_account_name(account_name)
            .with_account_key(account_key);
        self
    }

    /// Set SAS token for SAS authentication.
    pub fn with_sas_token(mut self, sas_token: impl Into<String>) -> Self {
        self.config_loader = self.config_loader.with_sas_token(sas_token);
        self
    }

    /// Set client credentials for service principal authentication.
    pub fn with_client_secret(
        mut self,
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        self.client_secret_loader = self
            .client_secret_loader
            .with_tenant_id(tenant_id)
            .with_client_id(client_id)
            .with_client_secret(client_secret);
        self
    }

    /// Set workload identity parameters for federated authentication.
    pub fn with_workload_identity(
        mut self,
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        federated_token_file: impl Into<String>,
    ) -> Self {
        self.workload_identity_loader = self
            .workload_identity_loader
            .with_tenant_id(tenant_id)
            .with_client_id(client_id)
            .with_federated_token_file(federated_token_file);
        self
    }

    /// Set IMDS parameters for managed identity authentication.
    pub fn with_imds(mut self) -> Self {
        self.imds_loader = ImdsLoader::new();
        self
    }

    /// Set custom IMDS endpoint.
    pub fn with_imds_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.imds_loader = self.imds_loader.with_endpoint(endpoint);
        self
    }

    /// Set client ID for user-assigned managed identity.
    pub fn with_imds_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.imds_loader = self.imds_loader.with_client_id(client_id);
        self
    }

    /// Set object ID for user-assigned managed identity.
    pub fn with_imds_object_id(mut self, object_id: impl Into<String>) -> Self {
        self.imds_loader = self.imds_loader.with_object_id(object_id);
        self
    }

    /// Set MSI resource ID for user-assigned managed identity.
    pub fn with_imds_msi_res_id(mut self, msi_res_id: impl Into<String>) -> Self {
        self.imds_loader = self.imds_loader.with_msi_res_id(msi_res_id);
        self
    }

    /// Set authority host for OAuth endpoints.
    pub fn with_authority_host(mut self, authority_host: impl Into<String>) -> Self {
        let host = authority_host.into();
        self.client_secret_loader = self.client_secret_loader.with_authority_host(host.clone());
        self.workload_identity_loader = self.workload_identity_loader.with_authority_host(host);
        self
    }

    /// Load credentials from environment variables.
    pub fn from_env(mut self, ctx: &Context) -> Self {
        // Load environment variables
        let account_name = ctx
            .env_var("AZBLOB_ACCOUNT_NAME")
            .or_else(|| ctx.env_var("AZURE_STORAGE_ACCOUNT_NAME"));
        let account_key = ctx
            .env_var("AZBLOB_ACCOUNT_KEY")
            .or_else(|| ctx.env_var("AZURE_STORAGE_ACCOUNT_KEY"));
        let sas_token = ctx.env_var("AZURE_STORAGE_SAS_TOKEN");

        let tenant_id = ctx.env_var("AZURE_TENANT_ID");
        let client_id = ctx.env_var("AZURE_CLIENT_ID");
        let client_secret = ctx.env_var("AZURE_CLIENT_SECRET");
        let federated_token_file = ctx.env_var("AZURE_FEDERATED_TOKEN_FILE");
        let authority_host = ctx
            .env_var("AZURE_AUTHORITY_HOST")
            .unwrap_or_else(|| "https://login.microsoftonline.com".to_string());

        // Configure loaders based on available environment variables
        if let (Some(account_name), Some(account_key)) = (account_name, account_key) {
            self.config_loader = self
                .config_loader
                .with_account_name(account_name)
                .with_account_key(account_key);
        }

        if let Some(sas_token) = sas_token {
            self.config_loader = self.config_loader.with_sas_token(sas_token);
        }

        if let (Some(tenant_id), Some(client_id), Some(client_secret)) =
            (tenant_id.clone(), client_id.clone(), client_secret)
        {
            self.client_secret_loader = self
                .client_secret_loader
                .with_tenant_id(tenant_id)
                .with_client_id(client_id)
                .with_client_secret(client_secret)
                .with_authority_host(authority_host.clone());
        }

        if let (Some(tenant_id), Some(client_id), Some(federated_token_file)) =
            (tenant_id, client_id.clone(), federated_token_file)
        {
            self.workload_identity_loader = self
                .workload_identity_loader
                .with_tenant_id(tenant_id)
                .with_client_id(client_id)
                .with_federated_token_file(federated_token_file)
                .with_authority_host(authority_host);
        }

        // Configure IMDS loader with optional parameters
        if let Some(client_id) = ctx.env_var("AZURE_CLIENT_ID") {
            self.imds_loader = self.imds_loader.with_client_id(client_id);
        }

        if let Some(object_id) = ctx.env_var("AZURE_OBJECT_ID") {
            self.imds_loader = self.imds_loader.with_object_id(object_id);
        }

        if let Some(msi_res_id) = ctx.env_var("AZURE_MSI_RES_ID") {
            self.imds_loader = self.imds_loader.with_msi_res_id(msi_res_id);
        }

        if let Some(endpoint) = ctx.env_var("AZURE_MSI_ENDPOINT") {
            self.imds_loader = self.imds_loader.with_endpoint(endpoint);
        }

        if let Some(secret) = ctx.env_var("AZURE_MSI_SECRET") {
            self.imds_loader = self.imds_loader.with_msi_secret(secret);
        }

        self
    }
}

#[async_trait]
impl ProvideCredential for DefaultLoader {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        // Try configuration loader first (account key, SAS token)
        if let Some(cred) = self.config_loader.provide_credential(ctx).await? {
            if cred.is_valid() {
                return Ok(Some(cred));
            }
        }

        // Try client secret loader
        if let Some(cred) = self.client_secret_loader.provide_credential(ctx).await? {
            if cred.is_valid() {
                return Ok(Some(cred));
            }
        }

        // Try workload identity loader
        if let Some(cred) = self.workload_identity_loader.provide_credential(ctx).await? {
            if cred.is_valid() {
                return Ok(Some(cred));
            }
        }

        // Try IMDS loader (managed identity)
        if let Some(cred) = self.imds_loader.provide_credential(ctx).await? {
            if cred.is_valid() {
                return Ok(Some(cred));
            }
        }

        Ok(None)
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
        let ctx = reqsign_core::Context::new(MockFileRead, MockHttpSend).with_env(env);

        let loader = DefaultLoader::new().from_env(&ctx);

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

        let ctx = reqsign_core::Context::new(MockFileRead, MockHttpSend).with_env(env);

        let loader = DefaultLoader::new().from_env(&ctx);

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
        async fn file_read(&self, _path: &str) -> anyhow::Result<Vec<u8>> {
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
        ) -> anyhow::Result<http::Response<bytes::Bytes>> {
            Ok(http::Response::new(bytes::Bytes::new()))
        }
    }
}
