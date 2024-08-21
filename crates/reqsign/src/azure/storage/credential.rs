use crate::time::DateTime;

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
    BearerToken(String, DateTime),
}

impl Credential {
    /// is current cred is valid?
    pub fn is_valid(&self) -> bool {
        if self.is_empty() {
            return false;
        }
        if let Credential::BearerToken(_, expires_on) = self {
            let buffer = chrono::TimeDelta::try_seconds(20).expect("in bounds");
            if expires_on < &(chrono::Utc::now() + buffer) {
                return false;
            }
        };

        true
    }

    fn is_empty(&self) -> bool {
        match self {
            Credential::SharedKey(account_name, account_key) => {
                account_name.is_empty() || account_key.is_empty()
            }
            Credential::SharedAccessSignature(sas_token) => sas_token.is_empty(),
            Credential::BearerToken(bearer_token, _) => bearer_token.is_empty(),
        }
    }
}
