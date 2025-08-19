use reqsign_azure_storage::{Credential, ImdsCredentialProvider};
use reqsign_core::{Context, OsEnv, ProvideCredential};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

fn is_test_enabled() -> bool {
    std::env::var("REQSIGN_AZURE_STORAGE_TEST_IMDS").unwrap_or_default() == "on"
}

#[tokio::test]
async fn test_imds_provider() {
    if !is_test_enabled() {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST_IMDS is not enabled");
        return;
    }

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let _client_id = std::env::var("AZURE_CLIENT_ID").ok();
    let _object_id = std::env::var("AZURE_OBJECT_ID").ok();
    let _msi_res_id = std::env::var("AZURE_MSI_RESOURCE_ID").ok();

    let loader = ImdsCredentialProvider::new();

    // This test will only succeed when running on Azure VM with managed identity
    let result = loader.provide_credential(&ctx).await;

    let cred = result
        .expect("IMDS provider should succeed when test is enabled")
        .expect("IMDS provider should return credentials when test is enabled");

    match cred {
        Credential::BearerToken {
            token,
            expires_in: _,
        } => {
            assert!(!token.is_empty());
            eprintln!("Successfully obtained bearer token from IMDS");
        }
        _ => panic!("Expected BearerToken credential from IMDS"),
    }
}

#[tokio::test]
async fn test_imds_provider_with_mock() {
    // This test uses a mock IMDS server
    // The mock server should be started before running this test
    if std::env::var("REQSIGN_AZURE_STORAGE_TEST_IMDS_MOCK").unwrap_or_default() != "on" {
        eprintln!("Skipping mock IMDS test: REQSIGN_AZURE_STORAGE_TEST_IMDS_MOCK is not enabled");
        return;
    }

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    // Save original endpoint to restore later
    let original_endpoint = std::env::var("AZURE_IMDS_ENDPOINT").ok();

    // Override IMDS endpoint to use mock server
    std::env::set_var("AZURE_IMDS_ENDPOINT", "http://localhost:8080");

    let loader = ImdsCredentialProvider::new();
    let result = loader.provide_credential(&ctx).await;

    // Restore original endpoint
    if let Some(endpoint) = original_endpoint {
        std::env::set_var("AZURE_IMDS_ENDPOINT", endpoint);
    } else {
        std::env::remove_var("AZURE_IMDS_ENDPOINT");
    }

    // Better error reporting
    let cred = match result {
        Ok(Some(cred)) => cred,
        Ok(None) => panic!("IMDS provider returned None when mock server is running"),
        Err(e) => panic!("IMDS provider failed with error: {e:?}\nError details: {e}"),
    };

    match cred {
        Credential::BearerToken {
            token,
            expires_in: _,
        } => {
            // The mock server returns a JWT-like token
            assert!(
                token.starts_with("eyJ0eX"),
                "Expected JWT token from mock server, got: {}",
                token
            );
            eprintln!("Successfully obtained bearer token from IMDS mock server");
        }
        _ => panic!("Expected BearerToken credential, got {:?}", cred),
    }
}
