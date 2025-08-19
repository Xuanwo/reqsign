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
