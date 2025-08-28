//! Huawei Cloud OBS service support with convenience APIs
//!
//! This module provides Huawei Cloud OBS signing functionality along with convenience
//! functions for common use cases.

// Re-export all Huawei Cloud OBS signing types
pub use reqsign_huaweicloud_obs::*;

#[cfg(feature = "default-context")]
use crate::{default_context, Signer};

/// Default Huawei Cloud OBS Signer type with commonly used components
#[cfg(feature = "default-context")]
pub type DefaultSigner = Signer<Credential>;

/// Create a default Huawei Cloud OBS signer with standard configuration
///
/// This function creates a signer with:
/// - Default context (with Tokio file reader, reqwest HTTP client, OS environment)
/// - Default credential provider (reads from env vars)
/// - Request signer for the specified bucket
///
/// # Example
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> reqsign_core::Result<()> {
/// // Create a signer for Huawei Cloud OBS bucket
/// let signer = reqsign::huaweicloud::default_signer("mybucket");
///
/// // Sign a request
/// let mut req = http::Request::builder()
///     .method("GET")
///     .uri("https://mybucket.obs.cn-north-1.myhuaweicloud.com/myobject")
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
