use anyhow::Result;
use async_trait::async_trait;
use reqsign_core::FileRead;

#[derive(Debug, Clone, Copy, Default)]
pub struct TokioFileRead;

#[async_trait]
impl FileRead for TokioFileRead {
    async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        tokio::fs::read(path).await.map_err(Into::into)
    }
}
