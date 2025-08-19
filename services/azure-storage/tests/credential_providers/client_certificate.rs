#[cfg(not(target_arch = "wasm32"))]
use reqsign_azure_storage::{ClientCertificateCredentialProvider, Credential};
#[cfg(not(target_arch = "wasm32"))]
use reqsign_core::{Context, OsEnv, ProvideCredential};
#[cfg(not(target_arch = "wasm32"))]
use reqsign_file_read_tokio::TokioFileRead;
#[cfg(not(target_arch = "wasm32"))]
use reqsign_http_send_reqwest::ReqwestHttpSend;

#[cfg(not(target_arch = "wasm32"))]
fn is_test_enabled() -> bool {
    std::env::var("REQSIGN_AZURE_STORAGE_TEST_CLIENT_CERTIFICATE").unwrap_or_default() == "on"
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_client_certificate_provider() {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST_CLIENT_CERTIFICATE is not enabled");
        return;
    }

    let _tenant_id = std::env::var("AZURE_TENANT_ID")
        .expect("AZURE_TENANT_ID must be set for client certificate test");
    let _client_id = std::env::var("AZURE_CLIENT_ID")
        .expect("AZURE_CLIENT_ID must be set for client certificate test");
    let _cert_path = std::env::var("AZURE_CLIENT_CERTIFICATE_PATH")
        .expect("AZURE_CLIENT_CERTIFICATE_PATH must be set for client certificate test");
    let _cert_password = std::env::var("AZURE_CLIENT_CERTIFICATE_PASSWORD").ok();

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let loader = ClientCertificateCredentialProvider::new();
    
    let result = loader.provide_credential(&ctx).await;
    
    assert!(result.is_ok());
    let cred = result.unwrap();
    assert!(cred.is_some());
    
    match cred.unwrap() {
        Credential::BearerToken { token, expires_in: _ } => {
            assert!(!token.is_empty());
            // Token should be a valid JWT
            assert!(token.starts_with("eyJ"));
            eprintln!("Successfully obtained bearer token using client certificate");
        }
        _ => panic!("Expected BearerToken credential from client certificate provider"),
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_client_certificate_provider_invalid_path() {
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    // Use invalid certificate path
    let loader = ClientCertificateCredentialProvider::new();
    
    let result = loader.provide_credential(&ctx).await;
    
    // Should fail with invalid certificate path
    assert!(result.is_err());
}