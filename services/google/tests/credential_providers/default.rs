use super::create_test_context_with_env;
use log::warn;
use reqsign_core::{ProvideCredential, Result};
use reqsign_google::DefaultCredentialProvider;
use std::collections::HashMap;
use std::env;

#[tokio::test]
async fn test_default_credential_provider() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_DEFAULT").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_DEFAULT is not set, skipped");
        return Ok(());
    }

    let cred_path = env::var("GOOGLE_APPLICATION_CREDENTIALS")
        .expect("GOOGLE_APPLICATION_CREDENTIALS must be set");

    let ctx = create_test_context_with_env(HashMap::from_iter([(
        "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
        cred_path,
    )]));

    let provider = DefaultCredentialProvider::new();
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
async fn test_default_credential_provider_with_json_file() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_DEFAULT").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_DEFAULT is not set, skipped");
        return Ok(());
    }

    // Test with test data file
    let test_file_path = format!(
        "{}/services/google/testdata/test_credential.json",
        env::current_dir()?.to_string_lossy()
    );

    let ctx = create_test_context_with_env(HashMap::from_iter([(
        "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
        test_file_path,
    )]));

    let provider = DefaultCredentialProvider::new();
    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("credential must be provided");

    assert!(credential.has_service_account());
    let sa = credential.service_account.as_ref().unwrap();
    assert_eq!(sa.client_email, "test-234@test.iam.gserviceaccount.com");

    Ok(())
}