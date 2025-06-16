//! Reqwest-based HTTP client implementation for reqsign.
//!
//! This crate provides `ReqwestHttpSend`, an HTTP client that implements
//! the `HttpSend` trait from `reqsign_core` using the popular reqwest library.
//!
//! ## Overview
//!
//! `ReqwestHttpSend` enables reqsign to send HTTP requests using reqwest's
//! powerful and feature-rich HTTP client. It handles the conversion between
//! standard `http` types and reqwest's types seamlessly.
//!
//! ## Example
//!
//! ```no_run
//! use reqsign_core::Context;
//! use reqsign_file_read_tokio::TokioFileRead;
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//! use reqwest::Client;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Use default client
//!     let ctx = Context::new(
//!         TokioFileRead::default(),
//!         ReqwestHttpSend::default(),
//!     );
//!
//!     // Or use a custom configured client
//!     let client = Client::builder()
//!         .timeout(std::time::Duration::from_secs(30))
//!         .build()
//!         .unwrap();
//!     
//!     let ctx = Context::new(
//!         TokioFileRead::default(),
//!         ReqwestHttpSend::new(client),
//!     );
//! }
//! ```
//!
//! ## Usage with Service Signers
//!
//! ```no_run
//! use reqsign_core::{Context, Signer};
//! use reqsign_file_read_tokio::TokioFileRead;
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//! use bytes::Bytes;
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Create context with reqwest HTTP client
//! let ctx = Context::new(
//!     TokioFileRead::default(),
//!     ReqwestHttpSend::default(),
//! );
//!
//! // The context can send HTTP requests
//! let req = http::Request::builder()
//!     .method("GET")
//!     .uri("https://api.example.com")
//!     .body(Bytes::new())?;
//!
//! let resp = ctx.http_send(req).await?;
//! println!("Response status: {}", resp.status());
//! # Ok(())
//! # }
//! ```
//!
//! ## Custom Client Configuration
//!
//! ```no_run
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//! use reqwest::Client;
//! use std::time::Duration;
//!
//! // Configure reqwest client with custom settings
//! let client = Client::builder()
//!     .timeout(Duration::from_secs(60))
//!     .pool_max_idle_per_host(10)
//!     .user_agent("my-app/1.0")
//!     .build()
//!     .unwrap();
//!
//! // Use the custom client
//! let http_send = ReqwestHttpSend::new(client);
//! ```

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::BodyExt;
use reqsign_core::HttpSend;
use reqwest::{Client, Request};

/// Reqwest-based implementation of the `HttpSend` trait.
///
/// This struct wraps a `reqwest::Client` and provides HTTP request
/// functionality for the reqsign ecosystem.
#[derive(Debug, Default)]
pub struct ReqwestHttpSend {
    client: Client,
}

impl ReqwestHttpSend {
    /// Create a new ReqwestHttpSend with a custom reqwest::Client.
    ///
    /// This allows you to configure the client with specific settings
    /// like timeouts, proxies, or custom headers.
    ///
    /// # Example
    ///
    /// ```
    /// use reqsign_http_send_reqwest::ReqwestHttpSend;
    /// use reqwest::Client;
    ///
    /// let client = Client::builder()
    ///     .timeout(std::time::Duration::from_secs(30))
    ///     .build()
    ///     .unwrap();
    ///
    /// let http_send = ReqwestHttpSend::new(client);
    /// ```
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl HttpSend for ReqwestHttpSend {
    async fn http_send(&self, req: http::Request<Bytes>) -> anyhow::Result<http::Response<Bytes>> {
        let req = Request::try_from(req)?;
        let resp: http::Response<_> = self.client.execute(req).await?.into();

        let (parts, body) = resp.into_parts();
        let bs = BodyExt::collect(body).await.map(|buf| buf.to_bytes())?;
        Ok(http::Response::from_parts(parts, bs))
    }
}
