//! Google Service Signer

mod constants;

mod credential;
pub use credential::Credential as GoogleCredential;
pub use credential::CredentialLoader as GoogleCredentialLoader;
pub use credential::{external_account, service_account};

mod token;
pub use token::Token as GoogleToken;
pub use token::TokenLoad as GoogleTokenLoad;
pub use token::TokenLoader as GoogleTokenLoader;

mod signer;
pub use signer::Signer as GoogleSigner;
