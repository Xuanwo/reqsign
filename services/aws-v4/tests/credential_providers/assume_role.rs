use super::create_test_context;
use log::info;
use reqsign_aws_v4::{AssumeRoleCredentialProvider, DefaultCredentialProvider, RequestSigner};
use reqsign_core::{ProvideCredential, Signer};
use std::env;

#[tokio::test]
async fn test_assume_role_credential_provider() {
    if env::var("REQSIGN_AWS_V4_TEST_ASSUME_ROLE").unwrap_or_default() != "on" {
        info!("REQSIGN_AWS_V4_TEST_ASSUME_ROLE not set, skipping");
        return;
    }

    let role_arn = env::var("REQSIGN_AWS_V4_ASSUME_ROLE_ARN")
        .expect("REQSIGN_AWS_V4_ASSUME_ROLE_ARN must be set for assume_role test");

    let ctx = create_test_context();
    let base_provider = DefaultCredentialProvider::new();
    let region = env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());

    // Create STS signer with base credentials
    let sts_signer = Signer::new(
        ctx.clone(),
        base_provider,
        RequestSigner::new("sts", &region),
    );

    let provider = AssumeRoleCredentialProvider::new(role_arn, sts_signer)
        .with_region(region.clone())
        .with_regional_sts_endpoint();

    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("AssumeRole should succeed");

    assert!(cred.is_some(), "AssumeRole should return credentials");
    let cred = cred.unwrap();
    assert!(!cred.access_key_id.is_empty());
    assert!(!cred.secret_access_key.is_empty());
    assert!(
        cred.session_token.is_some(),
        "AssumeRole should return session token"
    );
}
