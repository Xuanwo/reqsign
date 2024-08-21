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

#[cfg(feature = "services-aliyun")]
mod aliyun;
#[cfg(feature = "services-aliyun")]
pub use aliyun::*;

#[cfg(feature = "services-azblob")]
mod azure;
#[cfg(feature = "services-azblob")]
pub use azure::*;

#[cfg(feature = "services-google")]
mod google;
#[cfg(feature = "services-google")]
pub use google::*;

#[cfg(feature = "services-huaweicloud")]
mod huaweicloud;
#[cfg(feature = "services-huaweicloud")]
pub use huaweicloud::*;

#[cfg(feature = "services-oracle")]
mod oracle;
#[cfg(feature = "services-oracle")]
pub use oracle::*;

#[cfg(feature = "services-tencent")]
mod tencent;
#[cfg(feature = "services-tencent")]
pub use tencent::*;

mod sign;
pub use sign::Sign;

/// Signing context for request.
pub mod ctx;
pub mod dirs;
pub mod hash;
pub mod time;
