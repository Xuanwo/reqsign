use crate::env::{Env, OsEnv};
use crate::{FileRead, HttpSend};
use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::path::PathBuf;
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

    /// Read the file content entirely in `String`.
    pub async fn file_read_as_string(&self, path: &str) -> Result<String> {
        let bytes = self.file_read(path).await?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    /// Send http request and return the response.
    #[inline]
    pub async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        self.http.http_send(req).await
    }

    /// Send http request and return the response as string.
    pub async fn http_send_as_string(
        &self,
        req: http::Request<Bytes>,
    ) -> Result<http::Response<String>> {
        let (parts, body) = self.http.http_send(req).await?.into_parts();
        let body = String::from_utf8_lossy(&body).to_string();
        Ok(http::Response::from_parts(parts, body))
    }

    /// Get the home directory of the current user.
    #[inline]
    pub fn home_dir(&self) -> Option<PathBuf> {
        self.env.home_dir()
    }

    /// Expand `~` in input path.
    ///
    /// - If path not starts with `~/` or `~\\`, returns `Some(path)` directly.
    /// - Otherwise, replace `~` with home dir instead.
    /// - If home_dir is not found, returns `None`.
    pub fn expand_home_dir(&self, path: &str) -> Option<String> {
        if !path.starts_with("~/") && !path.starts_with("~\\") {
            Some(path.to_string())
        } else {
            self.home_dir()
                .map(|home| path.replace('~', &home.to_string_lossy()))
        }
    }

    /// Get the environment variable.
    ///
    /// - Returns `Some(v)` if the environment variable is found and is valid utf-8.
    /// - Returns `None` if the environment variable is not found or value is invalid.
    #[inline]
    pub fn env_var(&self, key: &str) -> Option<String> {
        self.env.var(key)
    }

    /// Returns an hashmap of (variable, value) pairs of strings, for all the
    /// environment variables of the current process.
    #[inline]
    pub fn env_vars(&self) -> HashMap<String, String> {
        self.env.vars()
    }
}
