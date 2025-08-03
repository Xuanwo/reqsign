use super::create_test_context_with_env;
use log::info;
use reqsign_aws_v4::AssumeRoleWithWebIdentityCredentialProvider;
use reqsign_core::ProvideCredential;
use std::collections::HashMap;
use std::env;

#[tokio::test]
async fn test_assume_role_with_web_identity_credential_provider() {
    if env::var("REQSIGN_AWS_V4_TEST_WEB_IDENTITY").unwrap_or_default() != "on" {
        info!("REQSIGN_AWS_V4_TEST_WEB_IDENTITY not set, skipping");
        return;
    }

    // Use AWS native environment variables
    let mut envs = HashMap::new();

    // Required variables
    envs.insert(
        "AWS_ROLE_ARN".to_string(),
        env::var("AWS_ROLE_ARN").expect("AWS_ROLE_ARN must be set"),
    );
    envs.insert(
        "AWS_WEB_IDENTITY_TOKEN_FILE".to_string(),
        env::var("AWS_WEB_IDENTITY_TOKEN_FILE")
            .expect("AWS_WEB_IDENTITY_TOKEN_FILE must be set"),
    );

    // Optional variables
    if let Ok(session_name) = env::var("AWS_ROLE_SESSION_NAME") {
        envs.insert("AWS_ROLE_SESSION_NAME".to_string(), session_name);
    }
    if let Ok(region) = env::var("AWS_REGION") {
        envs.insert("AWS_REGION".to_string(), region);
    }

    let ctx = create_test_context_with_env(envs);
    let provider = AssumeRoleWithWebIdentityCredentialProvider::new();

    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("AssumeRoleWithWebIdentity should succeed");

    assert!(
        cred.is_some(),
        "Should load credentials via web identity token"
    );
    let cred = cred.unwrap();
    assert!(!cred.access_key_id.is_empty());
    assert!(!cred.secret_access_key.is_empty());
    assert!(
        cred.session_token.is_some(),
        "Web identity should return session token"
    );
}