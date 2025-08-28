//! Tencent Cloud COS service support with convenience APIs
//!
//! This module provides Tencent Cloud COS signing functionality along with convenience
//! functions for common use cases.

// Re-export all Tencent Cloud COS signing types
pub use reqsign_tencent_cos::*;

#[cfg(feature = "default-context")]
use crate::{default_context, Signer};

/// Default Tencent Cloud COS Signer type with commonly used components
#[cfg(feature = "default-context")]
pub type DefaultSigner = Signer<Credential>;

/// Create a default Tencent Cloud COS signer with standard configuration
///
/// This function creates a signer with:
/// - Default context (with Tokio file reader, reqwest HTTP client, OS environment)
/// - Default credential provider (reads from env vars)
/// - Request signer for Tencent Cloud COS
///
/// # Example
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> reqsign_core::Result<()> {
/// // Create a signer for Tencent Cloud COS
/// let signer = reqsign::tencent::default_signer();
///
/// // Sign a request
/// let mut req = http::Request::builder()
///     .method("GET")
///     .uri("https://mybucket-1234567890.cos.ap-beijing.myqcloud.com/myobject")
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
