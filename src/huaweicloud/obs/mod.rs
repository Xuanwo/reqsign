//! Signers for huaweicloud obs service.

mod signer;
pub use signer::Signer as HuaweicloudObsSigner;

mod config;
pub use config::Config as HuaweicloudObsConfig;

mod credential;
pub use credential::Credential as HuaweicloudObsCredential;
pub use credential::CredentialLoader as HuaweicloudObsCredentialLoader;
