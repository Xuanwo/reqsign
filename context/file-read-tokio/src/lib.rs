//! Tokio-based file reading implementation for reqsign.
//!
//! This crate provides `TokioFileRead`, an async file reader that implements
//! the `FileRead` trait from `reqsign_core` using Tokio's file system operations.
//!
//! ## Overview
//!
//! `TokioFileRead` enables reqsign to read files asynchronously using Tokio's
//! efficient async I/O primitives. This is particularly useful when loading
//! credentials or configuration from the file system.
//!
//! ## Example
//!
//! ```no_run
//! use reqsign_core::Context;
//! use reqsign_file_read_tokio::TokioFileRead;
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create a context with Tokio file reader
//!     let ctx = Context::new(
//!         TokioFileRead::default(),
//!         ReqwestHttpSend::default(),
//!     );
//!
//!     // The context can now read files asynchronously
//!     match ctx.file_read("/path/to/credentials.json").await {
//!         Ok(content) => println!("Read {} bytes", content.len()),
//!         Err(e) => eprintln!("Failed to read file: {}", e),
//!     }
//! }
//! ```
//!
//! ## Usage with Service Signers
//!
//! ```no_run
//! use reqsign_core::{Context, Signer};
//! use reqsign_file_read_tokio::TokioFileRead;
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Many cloud services require reading credentials from files
//! let ctx = Context::new(
//!     TokioFileRead::default(),
//!     ReqwestHttpSend::default(),
//! );
//!
//! // Create a signer that can load credentials from files
//! // let signer = Signer::new(ctx, credential_loader, request_builder);
//! # Ok(())
//! # }
//! ```

use anyhow::Result;
use async_trait::async_trait;
use reqsign_core::FileRead;

/// Tokio-based implementation of the `FileRead` trait.
///
/// This struct provides async file reading capabilities using Tokio's
/// file system operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioFileRead;

#[async_trait]
impl FileRead for TokioFileRead {
    async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        tokio::fs::read(path).await.map_err(Into::into)
    }
}
