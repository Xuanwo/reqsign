//! Signers for huaweicloud obs service.

mod config;
pub use config::Config;

mod credential;
pub use credential::Credential;

mod sign_request;
pub use sign_request::RequestSigner;

mod provide_credential;
pub use provide_credential::{ConfigCredentialProvider, DefaultCredentialProvider};

mod constants;
