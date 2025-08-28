//! Oracle Cloud service support with convenience APIs
//!
//! This module provides Oracle Cloud signing functionality along with convenience
//! functions for common use cases.

// Re-export all Oracle Cloud signing types
pub use reqsign_oracle::*;

#[cfg(feature = "default-context")]
use crate::{default_context, Signer};

/// Default Oracle Cloud Signer type with commonly used components
#[cfg(feature = "default-context")]
pub type DefaultSigner = Signer<Credential>;

/// Create a default Oracle Cloud signer with standard configuration
///
/// This function creates a signer with:
/// - Default context (with Tokio file reader, reqwest HTTP client, OS environment)
/// - Default credential provider (reads from config file)
/// - Request signer for Oracle Cloud
///
/// # Example
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> reqsign_core::Result<()> {
/// // Create a signer for Oracle Cloud
/// let signer = reqsign::oracle::default_signer();
///
/// // Sign a request
/// let mut req = http::Request::builder()
///     .method("GET")
///     .uri("https://objectstorage.us-phoenix-1.oraclecloud.com/n/namespace/b/bucket/o/object")
///     .body(())
///     .unwrap()
///     .into_parts()
///     .0;
///     
/// signer.sign(&mut req, None).await?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "default-context")]
pub fn default_signer() -> DefaultSigner {
    let ctx = default_context();
    let provider = DefaultCredentialProvider::new();
    let signer = RequestSigner::new();
    Signer::new(ctx, provider, signer)
}
