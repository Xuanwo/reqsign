#[cfg(not(target_arch = "wasm32"))]
use reqsign_azure_storage::{AzureCliCredentialProvider, Credential};
#[cfg(not(target_arch = "wasm32"))]
use reqsign_command_execute_tokio::TokioCommandExecute;
#[cfg(not(target_arch = "wasm32"))]
use reqsign_core::{Context, OsEnv, ProvideCredential};
#[cfg(not(target_arch = "wasm32"))]
use reqsign_file_read_tokio::TokioFileRead;
#[cfg(not(target_arch = "wasm32"))]
use reqsign_http_send_reqwest::ReqwestHttpSend;

#[cfg(not(target_arch = "wasm32"))]
fn is_test_enabled() -> bool {
    std::env::var("REQSIGN_AZURE_STORAGE_TEST_CLI").unwrap_or_default() == "on"
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_azure_cli_provider() {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST_CLI is not enabled");
        return;
    }

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_command_execute(TokioCommandExecute)
        .with_env(OsEnv);

    let loader = AzureCliCredentialProvider::new();

    // This test requires Azure CLI to be installed and logged in
    let result = loader.provide_credential(&ctx).await;

    // Better error reporting
    let cred = match result {
        Ok(Some(cred)) => cred,
        Ok(None) => panic!("Azure CLI provider returned None when test is enabled"),
        Err(e) => panic!("Azure CLI provider failed with error: {e:?}"),
    };

    match cred {
        Credential::BearerToken {
            token,
            expires_in: _,
        } => {
            assert!(!token.is_empty());
            eprintln!("Successfully obtained bearer token from Azure CLI");
        }
        _ => panic!("Expected BearerToken credential from Azure CLI"),
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_azure_cli_provider_not_installed() {
    use std::env;

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_command_execute(TokioCommandExecute)
        .with_env(OsEnv);

    // Temporarily modify PATH to simulate Azure CLI not being installed
    let original_path = env::var("PATH").unwrap_or_default();
    env::set_var("PATH", "/nonexistent");

    let loader = AzureCliCredentialProvider::new();
    let result = loader.provide_credential(&ctx).await;

    // Restore original PATH
    env::set_var("PATH", original_path);

    // Should fail or return None when Azure CLI is not available
    assert!(result.is_err() || result.unwrap().is_none());
}
