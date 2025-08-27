//! AWS service support with convenience APIs
//!
//! This module provides AWS signing functionality along with convenience functions
//! for common use cases.

// Re-export all AWS signing types
pub use reqsign_aws_v4::*;

#[cfg(feature = "default-context")]
use crate::{default_context, Signer};

/// Default AWS Signer type with commonly used components
#[cfg(feature = "default-context")]
pub type DefaultSigner = Signer<Credential>;

/// Create a default AWS signer with standard configuration
///
/// This function creates a signer with:
/// - Default context (with Tokio file reader, reqwest HTTP client, OS environment)
/// - Default credential provider (reads from env vars, config files, IMDS, etc.)
/// - Request signer for the specified service and region
///
/// # Example
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> reqsign_core::Result<()> {
/// // Create a signer for S3 in us-east-1
/// let signer = reqsign::aws::default_signer("s3", "us-east-1");
///
/// // Sign a request
/// let mut req = http::Request::builder()
///     .method("GET")
///     .uri("https://s3.amazonaws.com/my-bucket/my-object")
///     .body(())
///     .unwrap()
///     .into_parts()
///     .0;
///     
/// signer.sign(&mut req, None).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Customization
///
/// You can customize the signer using the `with_*` methods:
///
/// ```no_run
/// # async fn example() -> reqsign_core::Result<()> {
/// use reqsign::aws::{default_signer, StaticCredentialProvider, SigningCredential};
///
/// let signer = default_signer("s3", "us-east-1")
///     .with_credential_provider(StaticCredentialProvider::new(SigningCredential {
///         access_key_id: "my-access-key".to_string(),
///         secret_access_key: "my-secret-key".to_string(),
///         session_token: None,
///         expires_in: None,
///     }));
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "default-context")]
pub fn default_signer(service: &str, region: &str) -> DefaultSigner {
    let ctx = default_context();
    let provider = DefaultCredentialProvider::new();
    let signer = RequestSigner::new(service, region);
    Signer::new(ctx, provider, signer)
}
