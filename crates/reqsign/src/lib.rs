//! Signing API requests without effort.
//!
//! # Services
//!
//! - [Aliyun OSS][crate::AliyunOssSigner] for Aliyun OSS.
//! - [AWS SigV4][`reqsign-aws-v4`] for AWS services like S3.
//! - [Azure Storage][crate::AzureStorageSigner] for Azure Storage services like Azure Blob Service.
//! - [Google][crate::GoogleSigner] for All google cloud services like Google Cloud Storage Service.
//! - [Huawei Cloud OBS][crate::HuaweicloudObsSigner] for Huawei Cloud Object Storage Service (OBS).

// Make sure all our public APIs have docs.
#![warn(missing_docs)]

mod sign;
pub use sign::*;

pub mod dirs;
pub mod hash;
pub mod time;

mod fs;
pub use fs::FileRead;
mod http;
pub use http::HttpSend;
mod env;
pub use env::Env;
mod context;
pub use context::Context;
