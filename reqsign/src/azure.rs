//! Azure Storage service support with convenience APIs
//!
//! This module provides Azure Storage signing functionality along with convenience
//! functions for common use cases.

// Re-export all Azure Storage signing types
pub use reqsign_azure_storage::*;

#[cfg(feature = "default-context")]
use crate::{default_context, Signer};

/// Default Azure Storage Signer type with commonly used components
#[cfg(feature = "default-context")]
pub type DefaultSigner = Signer<Credential>;

/// Create a default Azure Storage signer with standard configuration
///
/// This function creates a signer with:
/// - Default context (with Tokio file reader, reqwest HTTP client, OS environment)
/// - Default credential provider (reads from env vars, managed identity, CLI, etc.)
/// - Request signer for Azure Storage
///
/// # Example
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> reqsign_core::Result<()> {
/// // Create a signer for Azure Storage
/// let signer = reqsign::azure::default_signer();
///
/// // Sign a request
/// let mut req = http::Request::builder()
///     .method("GET")
///     .uri("https://myaccount.blob.core.windows.net/mycontainer/myblob")
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
/// use reqsign::azure::{default_signer, StaticCredentialProvider};
///
/// let signer = default_signer()
///     .with_credential_provider(StaticCredentialProvider::new_shared_key(
///         "myaccount",
///         "my-account-key",
///     ));
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
