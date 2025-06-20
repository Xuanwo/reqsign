use crate::provide_credential::{
    ClientSecretCredentialProvider, ConfigCredentialProvider, ImdsCredentialProvider,
    WorkloadIdentityCredentialProvider,
};
use crate::Credential;
use async_trait::async_trait;
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain};

/// Default loader that tries multiple credential sources in order.
///
/// The default loader attempts to load credentials from the following sources in order:
/// 1. Configuration (account key, SAS token)
/// 2. Client secret (service principal)
/// 3. Workload identity (federated credentials)
/// 4. IMDS (Azure VM managed identity)
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    chain: ProvideCredentialChain<Credential>,
}

impl Default for DefaultCredentialProvider {
    fn default() -> Self {
        let chain = ProvideCredentialChain::new()
            .push(ConfigCredentialProvider::new())
            .push(ClientSecretCredentialProvider::new())
            .push(WorkloadIdentityCredentialProvider::new())
            .push(ImdsCredentialProvider::new());

        Self { chain }
    }
}

impl DefaultCredentialProvider {
    /// Create a new default loader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load credentials from environment variables.
    pub fn from_env(self, ctx: &Context) -> Self {
        // Create providers configured from environment
        let mut config_loader = ConfigCredentialProvider::new();

        // Load environment variables for config
        let account_name = ctx
            .env_var("AZBLOB_ACCOUNT_NAME")
            .or_else(|| ctx.env_var("AZURE_STORAGE_ACCOUNT_NAME"));
        let account_key = ctx
            .env_var("AZBLOB_ACCOUNT_KEY")
            .or_else(|| ctx.env_var("AZURE_STORAGE_ACCOUNT_KEY"));
        let sas_token = ctx.env_var("AZURE_STORAGE_SAS_TOKEN");

        if let (Some(account_name), Some(account_key)) = (account_name, account_key) {
            config_loader = config_loader
                .with_account_name(account_name)
                .with_account_key(account_key);
        }

        if let Some(sas_token) = sas_token {
            config_loader = config_loader.with_sas_token(sas_token);
        }

        // Create client secret provider
        let mut client_secret_loader = ClientSecretCredentialProvider::new();
        let tenant_id = ctx.env_var("AZURE_TENANT_ID");
        let client_id = ctx.env_var("AZURE_CLIENT_ID");
        let client_secret = ctx.env_var("AZURE_CLIENT_SECRET");
        let authority_host = ctx
            .env_var("AZURE_AUTHORITY_HOST")
            .unwrap_or_else(|| "https://login.microsoftonline.com".to_string());

        if let (Some(tenant_id), Some(client_id), Some(client_secret)) =
            (tenant_id.clone(), client_id.clone(), client_secret)
        {
            client_secret_loader = client_secret_loader
                .with_tenant_id(tenant_id)
                .with_client_id(client_id)
                .with_client_secret(client_secret)
                .with_authority_host(authority_host.clone());
        }

        // Create workload identity provider
        let mut workload_identity_loader = WorkloadIdentityCredentialProvider::new();
        let federated_token_file = ctx.env_var("AZURE_FEDERATED_TOKEN_FILE");

        if let (Some(tenant_id), Some(client_id), Some(federated_token_file)) =
            (tenant_id, client_id.clone(), federated_token_file)
        {
            workload_identity_loader = workload_identity_loader
                .with_tenant_id(tenant_id)
                .with_client_id(client_id)
                .with_federated_token_file(federated_token_file)
                .with_authority_host(authority_host);
        }

        // Create IMDS provider
        let mut imds_loader = ImdsCredentialProvider::new();

        if let Some(client_id) = ctx.env_var("AZURE_CLIENT_ID") {
            imds_loader = imds_loader.with_client_id(client_id);
        }

        if let Some(object_id) = ctx.env_var("AZURE_OBJECT_ID") {
            imds_loader = imds_loader.with_object_id(object_id);
        }

        if let Some(msi_res_id) = ctx.env_var("AZURE_MSI_RES_ID") {
            imds_loader = imds_loader.with_msi_res_id(msi_res_id);
        }

        if let Some(endpoint) = ctx.env_var("AZURE_MSI_ENDPOINT") {
            imds_loader = imds_loader.with_endpoint(endpoint);
        }

        if let Some(secret) = ctx.env_var("AZURE_MSI_SECRET") {
            imds_loader = imds_loader.with_msi_secret(secret);
        }

        // Build new chain with configured providers
        let chain = ProvideCredentialChain::new()
            .push(config_loader)
            .push(client_secret_loader)
            .push(workload_identity_loader)
            .push(imds_loader);

        Self { chain }
    }
}

#[async_trait]
impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> reqsign_core::Result<Option<Self::Credential>> {
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
        let ctx = reqsign_core::Context::new(MockFileRead, MockHttpSend).with_env(env);

        let loader = DefaultCredentialProvider::new().from_env(&ctx);

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

        let loader = DefaultCredentialProvider::new().from_env(&ctx);

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
        async fn file_read(&self, _path: &str) -> reqsign_core::Result<Vec<u8>> {
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
        ) -> reqsign_core::Result<http::Response<bytes::Bytes>> {
            Ok(http::Response::new(bytes::Bytes::new()))
        }
    }
}
