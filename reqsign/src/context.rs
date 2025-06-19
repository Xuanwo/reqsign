use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use reqsign_core::{Env, FileRead, HttpSend};
use reqwest::Client;
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use tokio::fs;

#[derive(Debug, Default, Clone)]
pub struct DefaultContext {
    client: Client,
}

impl DefaultContext {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    pub fn with_client(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl FileRead for DefaultContext {
    async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        Ok(fs::read(path).await?)
    }
}

#[async_trait]
impl HttpSend for DefaultContext {
    async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        // Convert http::Request to reqwest::Request
        let method = req.method().clone();
        let uri = req.uri().to_string();
        let headers = req.headers().clone();
        let body = req.into_body();
        
        let mut reqwest_req = self.client.request(method, uri);
        reqwest_req = reqwest_req.headers(headers);
        reqwest_req = reqwest_req.body(body);
        
        let reqwest_resp = reqwest_req.send().await?;
        
        // Convert reqwest::Response to http::Response
        let status = reqwest_resp.status();
        let headers = reqwest_resp.headers().clone();
        let body = reqwest_resp.bytes().await?;
        
        let mut http_resp = http::Response::builder()
            .status(status);
        
        for (k, v) in headers {
            if let Some(name) = k {
                http_resp = http_resp.header(name, v);
            }
        }
        
        Ok(http_resp.body(body)?)
    }
}

impl Env for DefaultContext {
    fn var(&self, key: &str) -> Option<String> {
        env::var(key).ok()
    }

    fn vars(&self) -> HashMap<String, String> {
        env::vars().collect()
    }

    fn home_dir(&self) -> Option<PathBuf> {
        home::home_dir()
    }
}

