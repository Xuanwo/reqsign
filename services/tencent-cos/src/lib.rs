//! Tencent Cloud service signer
//!
//! Only COS has been supported.

mod constants;

mod config;
pub use config::Config;

mod credential;
pub use credential::Credential;

mod build;
pub use build::Builder;

pub mod load;
pub use load::{AssumeRoleWithWebIdentityLoader, ConfigLoader, DefaultLoader};
