//! Google Service Signer

mod constants;

mod credential;
mod oauth2;
pub use credential::{Credential, ServiceAccount, Token};

mod sign_request;
pub use sign_request::RequestSigner;

mod provide_credential;
pub use provide_credential::{
    DefaultCredentialProvider, StaticCredentialProvider, VmMetadataCredentialProvider,
};
