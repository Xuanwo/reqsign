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
//! use reqwest::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Create context with proper FileRead and HttpSend implementations
//!     let ctx = Context::new(file_reader, http_sender);
//!
//!     // Create a loader that tries multiple credential sources
//!     let loader = DefaultLoader::new().from_env(&ctx);
//!
//!     // Create a builder for Azure Storage
//!     let builder = Builder::new();
//!
//!     // Create the signer
//!     let signer = Signer::new(loader, builder);
//!
//!     // Build and sign your request
//!     let mut req = http::Request::get("https://account.blob.core.windows.net/container/blob")
//!         .body(reqwest::Body::default())?;
//!
//!     signer.sign(&ctx, &mut req).await?;
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

mod key;
pub use key::Credential;

mod build;
pub use build::Builder;

mod load;
pub use load::*;
