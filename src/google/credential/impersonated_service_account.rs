//! An impersonated service account.

#[derive(Clone, serde::Deserialize)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename_all = "snake_case")]
pub struct ImpersonatedServiceAccount {
    pub delegates: Vec<String>,
    pub service_account_impersonation_url: String,
    pub source_credentials: SourceCredentials,
}

#[derive(Clone, serde::Deserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct SourceCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,

    #[serde(rename = "type")]
    pub ty: String,
}
