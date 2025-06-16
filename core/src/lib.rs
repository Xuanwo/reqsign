//! Core components for signing API requests.
//!
//! This crate provides the foundational types and traits for the reqsign ecosystem.
//! It defines the core abstractions that enable flexible and extensible request signing.
//!
//! ## Overview
//!
//! The crate is built around several key concepts:
//!
//! - **Context**: A container that holds implementations for file reading, HTTP sending, and environment access
//! - **Traits**: Abstract interfaces for credential loading (`ProvideCredential`) and request signing (`SignRequest`)
//! - **Signer**: The main orchestrator that coordinates credential loading and request signing
//!
//! ## Example
//!
//! ```no_run
//! use reqsign_core::{Context, Signer, ProvideCredential, SignRequest, SigningCredential, SigningRequest};
//! use async_trait::async_trait;
//! use anyhow::Result;
//! use http::header::Parts;
//! use std::time::Duration;
//!
//! // Define your credential type
//! #[derive(Clone)]
//! struct MyCredential {
//!     key: String,
//!     secret: String,
//! }
//!
//! impl SigningCredential for MyCredential {
//!     fn is_valid(&self) -> bool {
//!         !self.key.is_empty() && !self.secret.is_empty()
//!     }
//! }
//!
//! // Implement credential loader
//! struct MyLoader;
//!
//! #[async_trait]
//! impl ProvideCredential for MyLoader {
//!     type Credential = MyCredential;
//!
//!     async fn provide_credential(&self, _: &Context) -> Result<Option<Self::Credential>> {
//!         Ok(Some(MyCredential {
//!             key: "my-access-key".to_string(),
//!             secret: "my-secret-key".to_string(),
//!         }))
//!     }
//! }
//!
//! // Implement request builder
//! struct MyBuilder;
//!
//! #[async_trait]
//! impl SignRequest for MyBuilder {
//!     type Credential = MyCredential;
//!
//!     async fn sign_request(
//!         &self,
//!         _ctx: &Context,
//!         _req: &mut Parts,
//!         _expires_in: Option<Duration>,
//!         _cred: &Self::Credential,
//!     ) -> Result<SigningRequest> {
//!         // Build your signing request here
//!         todo!()
//!     }
//! }
//!
//! # async fn example() -> Result<()> {
//! // Create a context with your implementations
//! let ctx = Context::default();
//!
//! // Create a signer
//! let signer = Signer::new(ctx, MyLoader, MyBuilder);
//!
//! // Sign your requests
//! let mut parts = http::Request::builder()
//!     .method("GET")
//!     .uri("https://example.com")
//!     .body(())
//!     .unwrap()
//!     .into_parts()
//!     .0;
//!     
//! signer.sign(&mut parts, None).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Traits
//!
//! This crate defines several important traits:
//!
//! - [`FileRead`]: For asynchronous file reading
//! - [`HttpSend`]: For sending HTTP requests
//! - [`Env`]: For environment variable access
//! - [`ProvideCredential`]: For loading credentials from various sources
//! - [`SignRequest`]: For building service-specific signing requests
//! - [`SigningCredential`]: For validating credentials
//!
//! ## Utilities
//!
//! The crate also provides utility modules:
//!
//! - [`hash`]: Cryptographic hashing utilities
//! - [`time`]: Time manipulation utilities
//! - [`utils`]: General utilities including data redaction

// Make sure all our public APIs have docs.
#![warn(missing_docs)]

pub mod hash;
pub mod time;
pub mod utils;

mod context;
pub use context::Context;
mod fs;
pub use fs::FileRead;
mod http;
pub use http::HttpSend;
mod env;
pub use env::Env;
pub use env::StaticEnv;

mod api;
pub use api::{ProvideCredential, SignRequest, SigningCredential};
mod request;
pub use request::{SigningMethod, SigningRequest};
mod signer;
pub use signer::Signer;
