//! Signing API requests without effort.
//!
//! # Example
//!
//! ```rust
//! use reqsign::services::aws::v4::Signer;
//! use reqwest::{Client, Request, Url};
//! use anyhow::Result;
//!
//! #[tokio::main]
//! async fn main() -> Result<()>{
//!     // Signer can load region and credentials from environment by default.
//!     let signer = Signer::builder()
//!         .service("s3")
//!         .region("test")
//!         .allow_anonymous()
//!         .build()?;
//!     // Construct request
//!     let url = Url::parse( "https://s3.amazonaws.com/testbucket")?;
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
//! - [AWS SigV4][crate::services::aws::v4::Signer] for AWS services like S3.
//! - [Azure Storage][crate::services::azure::storage::Signer] for Azure Storage services like Azure Blob Service.
//! - [Google][crate::services::google::Signer] for All google cloud services like Google Cloud Storage Service.

// Make sure all our public APIs have docs.
#![warn(missing_docs)]

pub mod request;
pub mod services;

pub(crate) mod dirs;
pub(crate) mod hash;
pub mod time;
