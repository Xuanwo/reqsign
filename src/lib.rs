//! Signing API requests without effort.
//!
//! # Example
//!
//! ```rust
//! use anyhow::Result;
//! use reqsign::AwsV4Signer;
//! use reqwest::Client;
//! use reqwest::Request;
//! use reqwest::Url;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Signer can load region and credentials from environment by default.
//!     let signer = AwsV4Signer::builder()
//!         .service("s3")
//!         .region("test")
//!         .allow_anonymous()
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
//! - [Azure Storage][crate::azure::storage::Signer] for Azure Storage services like Azure Blob Service.
//! - [Google][crate::google::Signer] for All google cloud services like Google Cloud Storage Service.
//! - [Huawei Cloud OBS][crate::huaweicloud::obs::Signer] for Huawei Cloud Object Storage Service (OBS).
//!
//! # Features
//!
//! reqsign support [`http::Request`] by default. Other request types support are hided
//! under feature gates to reduce dependencies.
//!
//! - `reqwest_request`: Enable to support signing [`reqwest::Request`]
//! - `reqwest_blocking_request`: Enable to support signing [`reqwest::blocking::Request`]
//! - `http_types_request`: Enable to support signing [`http_types::Request`]

// Make sure all our public APIs have docs.
#![warn(missing_docs)]

pub mod credential;

mod aliyun;
pub use aliyun::oss::Builder as AliyunOssBuilder;
pub use aliyun::oss::Signer as AliyunOssSigner;

mod aws;
pub use aws::v4::Builder as AwsV4Builder;
pub use aws::v4::Signer as AwsV4Signer;

pub mod azure;
pub mod google;
pub mod huaweicloud;

mod dirs;
mod hash;
mod request;
mod time;
