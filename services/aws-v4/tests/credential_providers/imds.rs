use super::create_test_context;
use log::info;
use reqsign_aws_v4::IMDSv2CredentialProvider;
use reqsign_core::ProvideCredential;
use std::env;

#[tokio::test]
async fn test_imds_v2_credential_provider() {
    if env::var("REQSIGN_AWS_V4_TEST_IMDS").unwrap_or_default() != "on" {
        info!("REQSIGN_AWS_V4_TEST_IMDS not set, skipping");
        return;
    }

    let ctx = create_test_context();
    let provider = IMDSv2CredentialProvider::new();

    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("IMDSv2CredentialProvider should succeed on EC2");

    assert!(
        cred.is_some(),
        "Should load credentials from EC2 instance metadata"
    );
    let cred = cred.unwrap();
    assert!(!cred.access_key_id.is_empty());
    assert!(!cred.secret_access_key.is_empty());
    assert!(
        cred.session_token.is_some(),
        "IMDS should return session token"
    );
}