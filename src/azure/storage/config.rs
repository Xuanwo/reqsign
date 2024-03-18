/// Config carries all the configuration for Azure Storage services.
#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug))]
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
    /// `azure_federated_token` value will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AZURE_FEDERATED_TOKEN`]
    /// - profile config: `azure_federated_token_file`
    pub azure_federated_token: Option<String>,
    /// `azure_federated_token_file` value will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AZURE_FEDERATED_TOKEN_FILE`]
    /// - profile config: `azure_federated_token_file`
    pub azure_federated_token_file: Option<String>,
    /// `azure_tenant_id_env_key` value will be loaded from:
    ///
    /// - this field if it's `is_some`
    /// - env value: [`AZURE_TENANT_ID_ENV_KEY`]
    /// - profile config: `azure_tenant_id_env_key`
    pub azure_tenant_id_env_key: Option<String>,
}
