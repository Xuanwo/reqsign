pub mod default;
pub mod env;
pub mod static_provider;

#[cfg(not(target_arch = "wasm32"))]
pub mod azure_cli;

#[cfg(not(target_arch = "wasm32"))]
pub mod client_certificate;

pub mod client_secret;
pub mod imds;
pub mod workload_identity;
pub mod azure_pipelines;