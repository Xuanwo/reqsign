use anyhow::Result;
use bytes::Bytes;
use std::fmt::Debug;

/// HttpSend is used to send http request during the signing process.
///
/// For example, fetch IMDS token from AWS or OAuth2 refresh token. This trait is designed
/// especially for the signer, please don't use it as a general http client.
#[async_trait::async_trait]
pub trait HttpSend: Debug + 'static {
    /// Send http request and return the response.
    async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>>;
}
