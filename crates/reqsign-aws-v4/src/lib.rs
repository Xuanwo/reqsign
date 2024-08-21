//! AWS service signer

mod config;
pub use config::Config;

mod credential;
pub use credential::AssumeRoleLoader;
pub use credential::Credential;
pub use credential::CredentialLoad;
pub use credential::DefaultLoader;

mod signer;
pub use signer::Signer;

mod constants;
