use reqsign_core::{Context, OsEnv};

#[cfg(not(target_arch = "wasm32"))]
use reqsign_command_execute_tokio::TokioCommandExecute;
#[cfg(not(target_arch = "wasm32"))]
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

/// Create a Context with default implementations.
///
/// This function returns a Context configured with:
/// - `TokioCommandExecute` for command execution (non-WASM only)
/// - `TokioFileRead` for file reading (non-WASM only)
/// - `ReqwestHttpSend` for HTTP requests
/// - `OsEnv` for environment variable access
///
/// # Example
///
/// ```no_run
/// # async fn example() -> reqsign_core::Result<()> {
/// let ctx = reqsign::default_context();
///
/// // Use the context directly
/// let response = ctx.http_send(http::Request::builder()
///     .uri("https://api.example.com")
///     .body(bytes::Bytes::new())?)
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// # Customization
///
/// You can replace any component by chaining method calls:
///
/// ```no_run
/// # async fn example() -> reqsign_core::Result<()> {
/// // Example: Replace with a custom environment implementation
/// use reqsign_core::StaticEnv;
/// use std::collections::HashMap;
///
/// let mut envs = HashMap::new();
/// envs.insert("AWS_ACCESS_KEY_ID".to_string(), "my-key".to_string());
///
/// let ctx = reqsign::default_context()
///     .with_env(StaticEnv { envs, home_dir: None });
/// # Ok(())
/// # }
/// ```
pub fn default_context() -> Context {
    #[cfg(not(target_arch = "wasm32"))]
    {
        Context::new()
            .with_command_execute(TokioCommandExecute)
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv)
    }

    #[cfg(target_arch = "wasm32")]
    {
        Context::new()
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv)
    }
}
