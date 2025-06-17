use anyhow::Result;

use crate::{connection_string, Credential, Service};

/// Config carries all the configuration for Azure Storage services.
#[derive(Clone, Default, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Config {
    /// Azure storage account name
    pub account_name: Option<String>,
    /// Azure storage account key
    pub account_key: Option<String>,
    /// SAS (Shared Access Signature) token
    pub sas_token: Option<String>,
    /// Azure tenant ID for OAuth authentication
    pub tenant_id: Option<String>,
    /// Azure client ID for OAuth authentication
    pub client_id: Option<String>,
    /// Azure client secret for OAuth authentication
    pub client_secret: Option<String>,
    /// Path to federated token file for workload identity
    pub federated_token_file: Option<String>,
    /// Authority host URL for OAuth endpoints
    pub authority_host: Option<String>,
    /// Object ID for user-assigned managed identity
    pub object_id: Option<String>,
    /// MSI resource ID for user-assigned managed identity
    pub msi_res_id: Option<String>,
    /// MSI secret header for managed identity authentication
    pub msi_secret: Option<String>,
    /// Custom IMDS endpoint URL
    pub endpoint: Option<String>,
}

impl Config {
    /// Create a new empty config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the account name.
    pub fn with_account_name(mut self, account_name: impl Into<String>) -> Self {
        self.account_name = Some(account_name.into());
        self
    }

    /// Set the account key.
    pub fn with_account_key(mut self, account_key: impl Into<String>) -> Self {
        self.account_key = Some(account_key.into());
        self
    }

    /// Set the SAS token.
    pub fn with_sas_token(mut self, sas_token: impl Into<String>) -> Self {
        self.sas_token = Some(sas_token.into());
        self
    }

    /// Set the tenant ID.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Set the client ID.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the client secret.
    pub fn with_client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Set the federated token file path.
    pub fn with_federated_token_file(mut self, federated_token_file: impl Into<String>) -> Self {
        self.federated_token_file = Some(federated_token_file.into());
        self
    }

    /// Set the authority host.
    pub fn with_authority_host(mut self, authority_host: impl Into<String>) -> Self {
        self.authority_host = Some(authority_host.into());
        self
    }

    /// Set the object ID.
    pub fn with_object_id(mut self, object_id: impl Into<String>) -> Self {
        self.object_id = Some(object_id.into());
        self
    }

    /// Set the MSI resource ID.
    pub fn with_msi_res_id(mut self, msi_res_id: impl Into<String>) -> Self {
        self.msi_res_id = Some(msi_res_id.into());
        self
    }

    /// Set the MSI secret.
    pub fn with_msi_secret(mut self, msi_secret: impl Into<String>) -> Self {
        self.msi_secret = Some(msi_secret.into());
        self
    }

    /// Set the IMDS endpoint.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Load config from environment variables for backward compatibility.
    ///
    /// Note that some values looked at by this method are specific to Azure
    /// Blob Storage.
    pub fn from_env(mut self) -> Self {
        use std::env;

        // Load environment variables
        if let Ok(v) = env::var("AZURE_FEDERATED_TOKEN_FILE") {
            self.federated_token_file = Some(v);
        }

        if let Ok(v) = env::var("AZURE_TENANT_ID") {
            self.tenant_id = Some(v);
        }

        if let Ok(v) = env::var("AZURE_CLIENT_ID") {
            self.client_id = Some(v);
        }

        if let Ok(v) = env::var("AZBLOB_ENDPOINT") {
            self.endpoint = Some(v);
        }

        if let Ok(v) = env::var("AZBLOB_ACCOUNT_KEY") {
            self.account_key = Some(v);
        }

        if let Ok(v) = env::var("AZBLOB_ACCOUNT_NAME") {
            self.account_name = Some(v);
        }

        if let Ok(v) = env::var("AZURE_AUTHORITY_HOST") {
            self.authority_host = Some(v);
        } else {
            self.authority_host = Some("https://login.microsoftonline.com".to_string());
        }

        if let Ok(v) = env::var("AZURE_CLIENT_SECRET") {
            self.client_secret = Some(v);
        }

        self
    }

    /// Parses an [Azure connection string][1] into a configuration object.
    ///
    /// The connection string doesn't have to specify all required parameters
    /// because the user is still allowed to set them later directly on the object.
    ///
    /// The function takes a Service parameter because it determines the fields used
    /// to parse the endpoint.
    ///
    /// An example of a connection string looks like:
    ///
    /// ```txt
    /// AccountName=mystorageaccount;
    /// AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;
    /// BlobEndpoint=https://mystorageaccount.blob.core.windows.net
    /// ```
    ///
    /// [1]: https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string
    pub fn try_from_connection_string(conn_str: &str, service: &Service) -> Result<Self> {
        connection_string::parse(conn_str, service)
    }
}

impl Config {
    pub(crate) fn with_credential(self, credential: Credential) -> Self {
        match credential {
            Credential::SasToken { token } => self.with_sas_token(token),
            Credential::SharedKey {
                account_name,
                account_key,
            } => self
                .with_account_name(account_name)
                .with_account_key(account_key),
            Credential::BearerToken {
                token: _,
                expires_in: _,
            } => self, // Bearer tokens are ignored.
        }
    }
}
