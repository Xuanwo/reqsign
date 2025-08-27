use super::{create_test_context, create_test_context_with_env};
use log::warn;
use reqsign_core::{ProvideCredential, Result};
use reqsign_google::VmMetadataCredentialProvider;
use std::collections::HashMap;
use std::env;

#[tokio::test]
async fn test_vm_metadata_credential_provider() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_VM_METADATA").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_VM_METADATA is not set, skipped");
        return Ok(());
    }

    // This test should only run on actual GCP VMs
    let ctx = create_test_context();

    let provider = VmMetadataCredentialProvider::new();
    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("credential must be provided on GCP VM");

    assert!(credential.has_token(), "Must have access token");
    assert!(credential.has_valid_token(), "Token must be valid");
    let token = credential.token.as_ref().unwrap();
    assert!(!token.access_token.is_empty(), "Token must not be empty");

    Ok(())
}

#[tokio::test]
async fn test_vm_metadata_credential_provider_with_scope() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_VM_METADATA").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_VM_METADATA is not set, skipped");
        return Ok(());
    }

    // This test allows specifying a custom scope
    let scope = env::var("REQSIGN_GOOGLE_SCOPE")
        .unwrap_or_else(|_| "https://www.googleapis.com/auth/devstorage.read_write".to_string());

    let ctx = create_test_context();

    let provider = VmMetadataCredentialProvider::new().with_scope(&scope);
    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("credential must be provided on GCP VM");

    assert!(credential.has_token(), "Must have access token");
    assert!(credential.has_valid_token(), "Token must be valid");

    Ok(())
}
