//! Azure Storage SharedKey support
//!
//! Use [`azure::storage::Signer`][crate::azure::storage::Signer]

mod account_sas;
mod client_secret_credential;
mod connection_string;
mod constants;
mod imds_credential;
mod workload_identity_credential;

mod signer;
pub use signer::Signer;

mod config;
pub use config::Config;

mod credential;
pub use credential::Credential;

mod loader;
pub use loader::Loader;

/// The Azure Storage service that a configuration or credential is used with.
#[derive(PartialEq)]
pub enum Service {
    /// Azure Blob Storage.
    Blob,

    /// Azure File Storage.
    File,

    /// Azure Queue Storage.
    Table,

    /// Azure Queue Storage.
    Queue,

    /// Azure Data Lake Storage Gen2.
    Adls,
}

impl Service {
    pub(crate) fn endpoint_name(&self) -> &str {
        match self {
            Service::Blob => "blob",
            Service::File => "file",
            Service::Table => "table",
            Service::Queue => "queue",
            Service::Adls => "dfs",
        }
    }
}
