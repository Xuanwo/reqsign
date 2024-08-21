//! Tencent Cloud service signer
//!
//! Only Cos has been supported.

mod cos;
pub use cos::Signer as TencentCosSigner;

mod credential;
pub use credential::Credential as TencentCosCredential;
pub use credential::CredentialLoader as TencentCosCredentialLoader;

mod config;
pub use config::Config as TencentCosConfig;

mod constants;
