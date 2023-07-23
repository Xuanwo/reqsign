//! AWS service signer
//!
//! Only sigv4 has been supported.
mod config;
pub use config::Config as AwsConfig;

mod credential;
pub use credential::AssumeRoleLoader as AwsAssumeRoleLoader;
pub use credential::Credential as AwsCredential;
pub use credential::CredentialLoad as AwsCredentialLoad;
pub use credential::DefaultLoader as AwsDefaultLoader;

mod v4;
pub use v4::Signer as AwsV4Signer;

mod constants;
