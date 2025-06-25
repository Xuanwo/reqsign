//! Oracle Cloud Infrastructure service signer
//!

mod constants;

mod config;
#[allow(deprecated)]
pub use config::Config;

mod credential;
pub use credential::Credential;

mod sign_request;
pub use sign_request::RequestSigner;

pub mod provide_credential;
#[allow(deprecated)]
pub use provide_credential::ConfigCredentialProvider;
pub use provide_credential::{
    ConfigFileCredentialProvider, DefaultCredentialProvider, EnvCredentialProvider,
    StaticCredentialProvider,
};
