//! A service account.

/// Credential is the file which stores service account's client_id and private key.
#[derive(Clone, serde::Deserialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename_all = "snake_case")]
pub struct ServiceAccount {
    /// Private key of credential
    pub private_key: String,
    /// The client email of credential
    pub client_email: String,
}
