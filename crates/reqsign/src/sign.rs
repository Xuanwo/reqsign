use std::time::Duration;

/// Sign will be a trait that implement by all services providers supported by reqsign, user
/// can implement their own too. It will take http::request::Parts and services Credential
/// to perform sign over this request.
#[async_trait::async_trait]
pub trait Sign: Send + Sync + Unpin + 'static {
    /// Credential type for this signer.
    type Credential: Send + Sync + Unpin + 'static;

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
