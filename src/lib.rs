//! Signing API requests without effort.
//!
//! # Example
//!
//! ```no_run
//! use anyhow::Result;
//! use reqsign::AwsConfigLoader;
//! use reqsign::AwsV4Signer;
//! use reqwest::Client;
//! use reqwest::Request;
//! use reqwest::Url;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Signer can load region and credentials from environment by default.
//!     let signer = AwsV4Signer::builder()
//!         .config_loader(AwsConfigLoader::with_loaded())
//!         .service("s3")
//!         .build()?;
//!     // Construct request
//!     let url = Url::parse("https://s3.amazonaws.com/testbucket")?;
//!     let mut req = reqwest::Request::new(http::Method::GET, url);
//!     // Signing request with Signer
//!     signer.sign(&mut req)?;
//!     // Sending already signed request.
//!     let resp = Client::new().execute(req).await?;
//!     println!("resp got status: {}", resp.status());
//!     Ok(())
//! }
//! ```
//!
//! # Available Services
//!
//! - [Aliyun OSS][crate::AliyunOssSigner] for Aliyun OSS.
//! - [AWS SigV4][crate::AwsV4Signer] for AWS services like S3.
//! - [Azure Storage][crate::AzureStorageSigner] for Azure Storage services like Azure Blob Service.
//! - [Google][crate::GoogleSigner] for All google cloud services like Google Cloud Storage Service.
//! - [Huawei Cloud OBS][crate::HuaweicloudObsSigner] for Huawei Cloud Object Storage Service (OBS).
//!
//! # Features
//!
//! reqsign support [`http::Request`] by default. Other request types support are hided
//! under feature gates to reduce dependencies.
//!
//! - `reqwest_request`: Enable to support signing [`reqwest::Request`]
//! - `reqwest_blocking_request`: Enable to support signing [`reqwest::blocking::Request`]

// Make sure all our public APIs have docs.
#![warn(missing_docs)]

#[cfg(feature = "services-aliyun")]
mod aliyun;
#[cfg(feature = "services-aliyun")]
pub use aliyun::*;

#[cfg(feature = "services-aws")]
mod aws;
#[cfg(feature = "services-aws")]
pub use aws::*;

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

#[cfg(feature = "services-tencent")]
mod tencent;
#[cfg(feature = "services-tencent")]
pub use tencent::*;

mod ctx;
mod dirs;
mod hash;
mod request;
mod time;
