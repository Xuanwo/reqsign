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
    /// `tenant_id` will be used to acquire an access token from Azure Instance Metadata Service (IMDS)
    ///
    /// - this field if it's `is_some`
    pub tenant_id: Option<String>,
    /// `client_id` will be used to acquire an access token from Azure Instance Metadata Service (IMDS)
    ///
    /// - this field if it's `is_some`
    pub client_secret: Option<String>,
    /// `client_secret` will be used to acquire an access token from Azure Instance Metadata Service (IMDS)
    ///
    /// - this field if it's `is_some`
    pub client_id: Option<String>,
}
