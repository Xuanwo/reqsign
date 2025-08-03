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

    let identity_pool_id = env::var("REQSIGN_AWS_V4_COGNITO_IDENTITY_POOL_ID")
        .expect("REQSIGN_AWS_V4_COGNITO_IDENTITY_POOL_ID must be set");

    let region = env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());

    let ctx = create_test_context();
    let provider = CognitoIdentityCredentialProvider::new()
        .with_identity_pool_id(identity_pool_id)
        .with_region(region);

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
