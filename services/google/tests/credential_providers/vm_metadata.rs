use super::create_test_context;
use log::warn;
use reqsign_core::{ProvideCredential, Result};
use reqsign_google::VmMetadataCredentialProvider;
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
    let credential = provider.provide_credential(&ctx).await?;

    // On a real GCP VM, this should provide a credential
    if let Some(cred) = credential {
        assert!(cred.has_token());
        assert!(cred.has_valid_token());
        let token = cred.token.as_ref().unwrap();
        assert!(!token.access_token.is_empty());
    } else {
        // Not running on GCP VM, which is expected in most CI environments
        warn!("Not running on GCP VM, no credential provided");
    }

    Ok(())
}

#[tokio::test]
async fn test_vm_metadata_credential_provider_with_scope() -> Result<()> {
    if env::var("REQSIGN_GOOGLE_TEST_VM_METADATA").unwrap_or_default() != "on" {
        warn!("REQSIGN_GOOGLE_TEST_VM_METADATA is not set, skipped");
        return Ok(());
    }

    // This test allows specifying a custom scope
    let scope = env::var("REQSIGN_GOOGLE_SCOPE").unwrap_or_else(|_| {
        "https://www.googleapis.com/auth/devstorage.read_write".to_string()
    });

    let ctx = create_test_context();

    let provider = VmMetadataCredentialProvider::new().with_scope(&scope);
    let credential = provider.provide_credential(&ctx).await?;

    if let Some(cred) = credential {
        assert!(cred.has_token());
        assert!(cred.has_valid_token());
    } else {
        warn!("Not running on GCP VM, no credential provided");
    }

    Ok(())
}