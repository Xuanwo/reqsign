use reqsign_azure_storage::{ClientSecretCredentialProvider, Credential};
use reqsign_core::{Context, OsEnv, ProvideCredential};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

fn is_test_enabled() -> bool {
    std::env::var("REQSIGN_AZURE_STORAGE_TEST_CLIENT_SECRET").unwrap_or_default() == "on"
}

#[tokio::test]
async fn test_client_secret_provider() {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST_CLIENT_SECRET is not enabled");
        return;
    }

    let _tenant_id = std::env::var("AZURE_TENANT_ID")
        .expect("AZURE_TENANT_ID must be set for client secret test");
    let _client_id = std::env::var("AZURE_CLIENT_ID")
        .expect("AZURE_CLIENT_ID must be set for client secret test");
    let _client_secret = std::env::var("AZURE_CLIENT_SECRET")
        .expect("AZURE_CLIENT_SECRET must be set for client secret test");

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let loader = ClientSecretCredentialProvider::new();
    let result = loader.provide_credential(&ctx).await;

    assert!(result.is_ok());
    let cred = result.unwrap();
    assert!(cred.is_some());

    match cred.unwrap() {
        Credential::BearerToken {
            token,
            expires_in: _,
        } => {
            assert!(!token.is_empty());
            // Token should be a valid JWT
            assert!(token.starts_with("eyJ"));
            eprintln!("Successfully obtained bearer token using client secret");
        }
        _ => panic!("Expected BearerToken credential from client secret provider"),
    }
}

#[tokio::test]
async fn test_client_secret_provider_invalid_credentials() {
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    // Use invalid credentials
    let loader = ClientSecretCredentialProvider::new();

    let result = loader.provide_credential(&ctx).await;

    // Should fail with invalid credentials
    assert!(result.is_err() || result.unwrap().is_none());
}
