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
//!     // Signer will load region and credentials from environment by default.
//!     let signer = Signer::builder().service("s3").build().await?;
//!     // Construct request
//!     let url = Url::parse( "https://s3.amazonaws.com/testbucket")?;
//!     let mut req = reqwest::Request::new(http::Method::GET, url);
//!     // Signing request with Signer
//!     signer.sign(&mut req).await?;
//!     // Sending already signed request.
//!     let resp = Client::new().execute(req).await?;
//!     println!("resp got status: {}", resp.status());
//!     Ok(())
//! }
//! ```
pub mod request;
pub mod services;

pub(crate) mod dirs;
pub(crate) mod hash;
pub(crate) mod time;
