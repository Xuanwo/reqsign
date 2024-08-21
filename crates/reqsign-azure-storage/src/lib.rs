//! Azure Storage SharedKey support
//!
//! Use [`azure::storage::Signer`][crate::azure::storage::Signer]

mod account_sas;
mod client_secret_credential;
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
