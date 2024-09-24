//! Aliyun service signer
//!
//! Only OSS has been supported.

mod signer;
pub use signer::Signer;

mod config;
pub use config::Config;

mod credential;
pub use credential::Credential;
pub use credential::Loader;

mod constants;
