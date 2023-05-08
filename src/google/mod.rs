//! Google Service Signer

mod constants;

mod credential;
pub use credential::CredentialAccount as GoogleAccount;
pub use credential::CredentialLoader as GoogleCredentialLoader;
pub use credential::ExternalAccount as GoogleExternalAccount;
pub use credential::ServiceAccount as GoogleCredential;
pub use credential::ServiceAccount as GoogleServiceAccount;
pub use credential::{external_account, service_account};

mod token;
pub use token::Token as GoogleToken;
pub use token::TokenLoad as GoogleTokenLoad;
pub use token::TokenLoader as GoogleTokenLoader;

mod signer;
pub use signer::Signer as GoogleSigner;
