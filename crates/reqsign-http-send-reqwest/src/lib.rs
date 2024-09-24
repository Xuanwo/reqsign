use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::BodyExt;
use reqsign_core::HttpSend;
use reqwest::{Client, Request};

#[derive(Debug, Default)]
pub struct ReqwestHttpSend {
    client: Client,
}

impl ReqwestHttpSend {
    /// Create a new ReqwestHttpSend with a reqwest::Client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl HttpSend for ReqwestHttpSend {
    async fn http_send(&self, req: http::Request<Bytes>) -> anyhow::Result<http::Response<Bytes>> {
        let req = Request::try_from(req)?;
        let resp: http::Response<_> = self.client.execute(req).await?.into();

        let (parts, body) = resp.into_parts();
        let bs = BodyExt::collect(body).await.map(|buf| buf.to_bytes())?;
        Ok(http::Response::from_parts(parts, bs))
    }
}
