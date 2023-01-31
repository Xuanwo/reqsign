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
//! - `http_types_request`: Enable to support signing [`http_types::Request`]

// Make sure all our public APIs have docs.
#![warn(missing_docs)]

pub mod credential;

mod aliyun;
pub use aliyun::oss::Builder as AliyunOssBuilder;
pub use aliyun::oss::Signer as AliyunOssSigner;

mod aws;
pub use aws::config::ConfigLoader as AwsConfigLoader;
pub use aws::credential::CredentialLoader as AwsCredentialLoader;
pub use aws::v4::Builder as AwsV4Builder;
pub use aws::v4::Signer as AwsV4Signer;
pub use credential::CredentialLoad as AwsCredentialLoad;

mod azure;
pub use azure::storage::Builder as AzureStorageBuilder;
pub use azure::storage::Signer as AzureStorageSigner;

mod google;
pub use google::v4::Authentication as GoogleV4Authentication;
pub use google::v4::Builder as GoogleV4Builder;
pub use google::v4::Config as GoogleV4Config;
pub use google::v4::Signer as GoogleV4Signer;
pub use google::Builder as GoogleBuilder;
pub use google::Signer as GoogleSigner;
pub use google::Token as GoogleToken;
pub use google::TokenLoad as GoogleTokenLoad;

mod huaweicloud;
pub use huaweicloud::obs::Builder as HuaweicloudObsBuilder;
pub use huaweicloud::obs::Signer as HuaweicloudObsSigner;

mod dirs;
mod hash;
mod request;
mod time;

pub(crate) mod utils;
