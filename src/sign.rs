use std::fmt::Debug;
use std::time::Duration;

/// On some cases like https://github.com/apache/iceberg-rust/issues/506, user may want to
/// implement their own signing logic for their own services. This trait is defined to
/// allow user to inject their own signing logic.
#[async_trait::async_trait]
pub trait Sign: Debug + Send + Sync + Unpin + 'static {
    /// Credential type for this signer.
    type Credential: Debug + Send + Sync + Unpin + 'static;

    /// Sign the request with headers.
    async fn sign(
        &self,
        req: &mut http::request::Parts,
        cred: &Self::Credential,
    ) -> anyhow::Result<()>;

    /// Sign the request with query parameters.
    async fn sign_query(
        &self,
        req: &mut http::request::Parts,
        expires: Duration,
        cred: &Self::Credential,
    ) -> anyhow::Result<()>;
}
