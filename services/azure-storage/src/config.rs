use std::collections::HashMap;
use std::env;

use anyhow::Result;

use crate::{connection_string, Service};

/// Config carries all the configuration for Azure Storage services.
#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Config {
    /// `account_name` will be loaded from
    ///
    /// - this field if it's `is_some`
    pub account_name: Option<String>,
    /// `account_key` will be loaded from
    ///
    /// - this field if it's `is_some`
    pub account_key: Option<String>,
    /// `sas_token` will be loaded from
    ///
    /// - this field if it's `is_some`
    pub sas_token: Option<String>,
    /// Specifies the object id associated with a user assigned managed service identity resource
    ///
    /// The values of client_id and msi_res_id are discarded
    ///
    /// This is part of use AAD(Azure Active Directory) authenticate on Azure VM
    pub object_id: Option<String>,
    /// Specifies the application id (client id) associated with a user assigned managed service identity resource
    ///
    /// The values of object_id and msi_res_id are discarded
    /// - cnv value: [`AZURE_CLIENT_ID`]
    ///
    /// This is part of use AAD(Azure Active Directory) authenticate on Azure VM
    pub client_id: Option<String>,
    /// Specifies the ARM resource id of the user assigned managed service identity resource
    ///
    /// The values of object_id and client_id are discarded
    ///
    /// This is part of use AAD(Azure Active Directory) authenticate on Azure VM
    pub msi_res_id: Option<String>,
    /// Specifies the header that should be used to retrieve the access token.
    ///
    /// This header mitigates server-side request forgery (SSRF) attacks.
    ///
    /// This is part of use AAD(Azure Active Directory) authenticate on Azure VM
    pub msi_secret: Option<String>,
    /// Specifies the endpoint from which the identity should be retrieved.
    ///
    /// If not specified, the default endpoint of `http://169.254.169.254/metadata/identity/oauth2/token` will be used.
    ///
    /// This is part of use AAD(Azure Active Directory) authenticate on Azure VM
    pub endpoint: Option<String>,
    /// `federated_token_file` value will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AZURE_FEDERATED_TOKEN_FILE`]
    /// - profile config: `federated_token_file`
    pub federated_token_file: Option<String>,
    /// `tenant_id` value will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AZURE_TENANT_ID`]
    /// - profile config: `tenant_id`
    pub tenant_id: Option<String>,
    /// `authority_host` value will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AZURE_AUTHORITY_HOST`]
    /// - profile config: `authority_host`
    pub authority_host: Option<String>,

    /// `client_secret` value will be loaded from:
    /// - this field if it's `is_some`
    /// - profile config: `client_secret`
    /// - env value: `AZURE_CLIENT_SECRET`
    pub client_secret: Option<String>,
}

pub const AZURE_FEDERATED_TOKEN_FILE: &str = "AZURE_FEDERATED_TOKEN_FILE";
pub const AZURE_TENANT_ID: &str = "AZURE_TENANT_ID";
pub const AZURE_CLIENT_ID: &str = "AZURE_CLIENT_ID";
pub const AZURE_CLIENT_SECRET: &str = "AZURE_CLIENT_SECRET";
pub const AZURE_AUTHORITY_HOST: &str = "AZURE_AUTHORITY_HOST";
const AZBLOB_ENDPOINT: &str = "AZBLOB_ENDPOINT";
const AZBLOB_ACCOUNT_KEY: &str = "AZBLOB_ACCOUNT_KEY";
const AZBLOB_ACCOUNT_NAME: &str = "AZBLOB_ACCOUNT_NAME";
const AZURE_PUBLIC_CLOUD: &str = "https://login.microsoftonline.com";

impl Config {
    /// Load config from env.
    ///
    /// Note that some values looked at by this method are specific to Azure
    /// Blob Storage.
    pub fn from_env(mut self) -> Self {
        let envs = env::vars().collect::<HashMap<_, _>>();

        // federated_token can be loaded from both `AZURE_FEDERATED_TOKEN` and `AZURE_FEDERATED_TOKEN_FILE`.
        if let Some(v) = envs.get(AZURE_FEDERATED_TOKEN_FILE) {
            self.federated_token_file = Some(v.to_string());
        }

        if let Some(v) = envs.get(AZURE_TENANT_ID) {
            self.tenant_id = Some(v.to_string());
        }

        if let Some(v) = envs.get(AZURE_CLIENT_ID) {
            self.client_id = Some(v.to_string());
        }

        if let Some(v) = envs.get(AZBLOB_ENDPOINT) {
            self.endpoint = Some(v.to_string());
        }

        if let Some(v) = envs.get(AZBLOB_ACCOUNT_KEY) {
            self.account_key = Some(v.to_string());
        }

        if let Some(v) = envs.get(AZBLOB_ACCOUNT_NAME) {
            self.account_name = Some(v.to_string());
        }

        if let Some(v) = envs.get(AZURE_AUTHORITY_HOST) {
            self.authority_host = Some(v.to_string());
        } else {
            self.authority_host = Some(AZURE_PUBLIC_CLOUD.to_string());
        }

        if let Some(v) = envs.get(AZURE_CLIENT_SECRET) {
            self.client_secret = Some(v.to_string());
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
