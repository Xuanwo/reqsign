use crate::env::{Env, OsEnv};
use crate::{FileRead, HttpSend};
use anyhow::Result;
use bytes::Bytes;
use std::sync::Arc;

/// Context provides the context for the request signing.
#[derive(Debug, Clone)]
pub struct Context {
    fs: Arc<dyn FileRead>,
    http: Arc<dyn HttpSend>,
    env: Arc<dyn Env>,
}

impl Context {
    /// Create a new context.
    #[inline]
    pub fn new(fs: impl FileRead, http: impl HttpSend) -> Self {
        Self {
            fs: Arc::new(fs),
            http: Arc::new(http),
            env: Arc::new(OsEnv),
        }
    }

    /// Set the environment for the context. Use this if you want to mock the environment.
    #[inline]
    pub fn with_env(mut self, env: impl Env) -> Self {
        self.env = Arc::new(env);
        self
    }

    /// Read the file content entirely in `Vec<u8>`.
    #[inline]
    pub async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        self.fs.file_read(path).await
    }

    /// Send http request and return the response.
    #[inline]
    pub async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        self.http.http_send(req).await
    }
}
