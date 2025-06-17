mod config;
pub use config::ConfigLoader;

mod default;
pub use default::DefaultLoader;

mod imds;
pub use imds::ImdsLoader;

mod workload_identity;
pub use workload_identity::WorkloadIdentityLoader;

mod client_secret;
pub use client_secret::ClientSecretLoader;
