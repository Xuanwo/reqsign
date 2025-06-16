//! Azure Storage service signer
//!
//! This crate provides signing capabilities for Azure Storage services including:
//! - Shared Key authentication
//! - SAS (Shared Access Signature) token authentication
//! - Bearer token authentication (OAuth)
//!
//! # Example
//!
//! ```rust,no_run
//! use anyhow::Result;
//! use reqsign_azure_storage::{Config, DefaultLoader, Builder};
//! use reqsign_core::{Context, Signer};
//! use reqsign_file_read_tokio::TokioFileRead;
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//! use reqwest::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Create context with proper FileRead and HttpSend implementations
//!     let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
//!
//!     // Create a loader that tries multiple credential sources
//!     let loader = DefaultLoader::new().from_env(&ctx);
//!
//!     // Create a builder for Azure Storage
//!     let builder = Builder::new();
//!
//!     // Create the signer
//!     let signer = Signer::new(ctx.clone(), loader, builder);
//!
//!     // Build and sign your request
//!     let mut req = http::Request::get("https://account.blob.core.windows.net/container/blob")
//!         .body(reqwest::Body::default())?;
//!
//!     let (mut parts, body) = req.into_parts();
//!     signer.sign(&mut parts, None).await?;
//!     let req = http::Request::from_parts(parts, body);
//!
//!     // Send the signed request
//!     let resp = Client::new().execute(req.try_into()?).await?;
//!     println!("Response: {}", resp.status());
//!
//!     Ok(())
//! }
//! ```

mod account_sas;
mod constants;

mod config;
pub use config::Config;

mod credential;
pub use credential::Credential;

mod build;
pub use build::Builder;

mod load;
pub use load::*;
