//! Google Service Signer

mod constants;

mod config;
pub use config::Config;

mod credential;
pub use credential::{Credential, ServiceAccount, Token};

mod sign_request;
pub use sign_request::RequestSigner;

mod provide_credential;
pub use provide_credential::{
    AuthorizedUserCredentialProvider, ConfigCredentialProvider, DefaultCredentialProvider,
    ExternalAccountCredentialProvider, ImpersonatedServiceAccountCredentialProvider,
    VmMetadataCredentialProvider,
};
