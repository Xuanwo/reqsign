//! Tencent Cloud service signer
//!
//! Only Cos has been supported.

mod signer;
pub use signer::Signer;

mod credential;
pub use credential::Credential;
pub use credential::CredentialLoader;

mod config;
pub use config::Config;

mod constants;
