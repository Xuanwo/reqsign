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

#[cfg(feature = "services-oracle")]
mod oracle;
#[cfg(feature = "services-oracle")]
pub use oracle::*;

mod sign;
pub use sign::Sign;

/// Signing context for request.
pub mod ctx;
pub mod dirs;
pub mod hash;
pub mod time;
