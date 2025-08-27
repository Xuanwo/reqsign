use super::create_test_context;
use log::warn;
use reqsign_core::{ProvideCredential, Result};
use reqsign_google::StaticCredentialProvider;
use std::env;

#[tokio::test]
async fn test_static_credential_provider() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_STATIC").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_STATIC is not set, skipped");
        return Ok(());
    }

    let credential_content =
        env::var("REQSIGN_GOOGLE_CREDENTIAL").expect("REQSIGN_GOOGLE_CREDENTIAL must be set");

    let ctx = create_test_context();

    let provider = StaticCredentialProvider::from_base64(credential_content)
        .expect("credential must be valid base64");
    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("credential must be provided");

    assert!(credential.has_service_account());
    let sa = credential.service_account.as_ref().unwrap();
    assert!(!sa.client_email.is_empty());
    assert!(!sa.private_key.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_static_credential_provider_with_scope() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_STATIC").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_STATIC is not set, skipped");
        return Ok(());
    }

    let credential_content =
        env::var("REQSIGN_GOOGLE_CREDENTIAL").expect("REQSIGN_GOOGLE_CREDENTIAL must be set");
    let scope = env::var("REQSIGN_GOOGLE_CLOUD_STORAGE_SCOPE")
        .unwrap_or_else(|_| "https://www.googleapis.com/auth/devstorage.read_write".to_string());

    let ctx = create_test_context();

    let provider = StaticCredentialProvider::from_base64(credential_content)
        .expect("credential must be valid base64")
        .with_scope(&scope);
    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("credential must be provided");

    assert!(credential.has_service_account());
    // When a scope is provided, the provider may also fetch a token
    if credential.has_token() {
        assert!(credential.has_valid_token());
    }

    Ok(())
}
