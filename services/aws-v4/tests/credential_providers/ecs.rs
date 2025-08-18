use super::create_test_context_with_env;
use log::info;
use reqsign_aws_v4::ECSCredentialProvider;
use reqsign_core::ProvideCredential;
use std::collections::HashMap;
use std::env;

#[tokio::test]
async fn test_ecs_credential_provider() {
    if env::var("REQSIGN_AWS_V4_TEST_ECS").unwrap_or_default() != "on" {
        info!("REQSIGN_AWS_V4_TEST_ECS not set, skipping");
        return;
    }

    let mut envs = HashMap::new();

    // Add custom metadata endpoint if set (for testing)
    if let Ok(metadata_uri) = env::var("ECS_CONTAINER_METADATA_URI") {
        envs.insert("ECS_CONTAINER_METADATA_URI".to_string(), metadata_uri);
    }

    // ECS can use either relative or full URI
    if let Ok(relative_uri) = env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
        envs.insert(
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI".to_string(),
            relative_uri,
        );
    } else if let Ok(full_uri) = env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
        envs.insert("AWS_CONTAINER_CREDENTIALS_FULL_URI".to_string(), full_uri);
        // Full URI also requires authorization token
        if let Ok(token) = env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN") {
            envs.insert("AWS_CONTAINER_AUTHORIZATION_TOKEN".to_string(), token);
        }
    } else {
        panic!("Either AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or AWS_CONTAINER_CREDENTIALS_FULL_URI must be set");
    }

    let ctx = create_test_context_with_env(envs);
    let provider = ECSCredentialProvider::new();

    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("ECSCredentialProvider should succeed");

    assert!(cred.is_some(), "Should load credentials from ECS");
    let cred = cred.unwrap();
    assert!(!cred.access_key_id.is_empty());
    assert!(!cred.secret_access_key.is_empty());
}
