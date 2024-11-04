use anyhow::Result;
use std::fmt::Debug;

/// FileRead is used to read the file content entirely in `Vec<u8>`.
///
/// This could be used by `Load` to load the credential from the file.
#[async_trait::async_trait]
pub trait FileRead: Debug + Send + Sync + 'static {
    /// Read the file content entirely in `Vec<u8>`.
    async fn file_read(&self, path: &str) -> Result<Vec<u8>>;
}
