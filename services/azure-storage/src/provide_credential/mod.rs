mod env;
pub use env::EnvCredentialProvider;

mod static_provider;
pub use static_provider::StaticCredentialProvider;

mod default;
pub use default::DefaultCredentialProvider;

mod imds;
pub use imds::ImdsCredentialProvider;

mod workload_identity;
pub use workload_identity::WorkloadIdentityCredentialProvider;

mod client_secret;
pub use client_secret::ClientSecretCredentialProvider;

mod azure_cli;
pub use azure_cli::AzureCliCredentialProvider;
