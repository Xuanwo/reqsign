//! Aliyun service signer
//!
//! Only OSS has been supported.

mod oss;
pub use oss::Signer as AliyunOssSigner;

mod config;
pub use config::Config as AliyunConfig;

mod credential;
pub use credential::Credential as AliyunCredential;
pub use credential::Loader as AliyunLoader;

mod constants;
