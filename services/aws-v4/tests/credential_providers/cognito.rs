use super::create_test_context;
use log::info;
use reqsign_aws_v4::CognitoIdentityCredentialProvider;
use reqsign_core::ProvideCredential;
use std::env;

#[tokio::test]
async fn test_cognito_identity_credential_provider() {
    if env::var("REQSIGN_AWS_V4_TEST_COGNITO").unwrap_or_default() != "on" {
        info!("REQSIGN_AWS_V4_TEST_COGNITO not set, skipping");
        return;
    }

    // Provider will read configuration from environment variables:
    // - AWS_COGNITO_IDENTITY_POOL_ID
    // - AWS_REGION or AWS_DEFAULT_REGION
    // - AWS_COGNITO_ENDPOINT (for mock server)
    let ctx = create_test_context();
    let provider = CognitoIdentityCredentialProvider::new();

    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("CognitoIdentity should succeed");

    assert!(cred.is_some(), "Should load credentials from Cognito");
    let cred = cred.unwrap();
    assert!(!cred.access_key_id.is_empty());
    assert!(!cred.secret_access_key.is_empty());
    assert!(
        cred.session_token.is_some(),
        "Cognito should return session token"
    );
}
