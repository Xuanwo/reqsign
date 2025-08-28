//! Aliyun OSS service support with convenience APIs
//!
//! This module provides Aliyun OSS signing functionality along with convenience
//! functions for common use cases.

// Re-export all Aliyun OSS signing types
pub use reqsign_aliyun_oss::*;

#[cfg(feature = "default-context")]
use crate::{default_context, Signer};

/// Default Aliyun OSS Signer type with commonly used components
#[cfg(feature = "default-context")]
pub type DefaultSigner = Signer<Credential>;

/// Create a default Aliyun OSS signer with standard configuration
///
/// This function creates a signer with:
/// - Default context (with Tokio file reader, reqwest HTTP client, OS environment)
/// - Default credential provider (reads from env vars, config files, ECS metadata, etc.)
/// - Request signer for the specified bucket
///
/// # Example
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> reqsign_core::Result<()> {
/// // Create a signer for Aliyun OSS bucket
/// let signer = reqsign::aliyun::default_signer("mybucket");
///
/// // Sign a request
/// let mut req = http::Request::builder()
///     .method("GET")
///     .uri("https://mybucket.oss-cn-hangzhou.aliyuncs.com/myobject")
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
pub fn default_signer(bucket: &str) -> DefaultSigner {
    let ctx = default_context();
    let provider = DefaultCredentialProvider::new();
    let signer = RequestSigner::new(bucket);
    Signer::new(ctx, provider, signer)
}
