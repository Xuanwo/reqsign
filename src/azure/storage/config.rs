use crate::azure::storage::imds_credential::ImdsCredential;

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
    /// Will load credential from IMDS if it's `is_some`.
    pub imds_credential: Option<ImdsCredential>,
}
