//! Tencent Cloud service signer
//!
//! Only COS has been supported.

mod constants;

mod config;
pub use config::Config;

mod credential;
pub use credential::Credential;

mod sign_request;
pub use sign_request::RequestSigner;

pub mod provide_credential;
pub use provide_credential::{
    AssumeRoleWithWebIdentityCredentialProvider, ConfigCredentialProvider,
    DefaultCredentialProvider,
};
