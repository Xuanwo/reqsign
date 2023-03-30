//! Aliyun service signer
//!
//! Only OSS has been supported.

mod oss;
pub use oss::Signer as AliyunOssSigner;

mod config;
pub use config::Config as AliyunConfig;

mod loader;
pub use loader::Loader as AliyunLoader;

mod constants;
