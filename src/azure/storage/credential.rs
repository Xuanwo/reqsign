/// Credential that holds the access_key and secret_key.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub enum Credential {
    /// Credential via account key
    ///
    /// Refer to <https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key>
    SharedKey(String, String),
    /// Credential via SAS token
    ///
    /// Refer to <https://learn.microsoft.com/en-us/rest/api/storageservices/create-account-sas>
    SharedAccessSignature(String),
    /// Create an Bearer Token based credential
    ///
    /// Azure Storage accepts OAuth 2.0 access tokens from the Azure AD tenant
    /// associated with the subscription that contains the storage account.
    ///
    /// ref: <https://docs.microsoft.com/rest/api/storageservices/authorize-with-azure-active-directory>
    BearerToken(String),
}
