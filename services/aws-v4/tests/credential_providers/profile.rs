use super::create_test_context_with_env;
use log::info;
use reqsign_aws_v4::ProfileCredentialProvider;
use reqsign_core::ProvideCredential;
use std::collections::HashMap;
use std::env;

#[tokio::test]
async fn test_profile_credential_provider() {
    if env::var("REQSIGN_AWS_V4_TEST_PROFILE").unwrap_or_default() != "on" {
        info!("REQSIGN_AWS_V4_TEST_PROFILE not set, skipping");
        return;
    }

    let mut envs = HashMap::new();

    // Optional AWS profile name
    if let Ok(profile) = env::var("AWS_PROFILE") {
        envs.insert("AWS_PROFILE".to_string(), profile);
    }

    // Optional config file paths
    if let Ok(config_file) = env::var("AWS_CONFIG_FILE") {
        envs.insert("AWS_CONFIG_FILE".to_string(), config_file);
    }

    if let Ok(creds_file) = env::var("AWS_SHARED_CREDENTIALS_FILE") {
        envs.insert("AWS_SHARED_CREDENTIALS_FILE".to_string(), creds_file);
    }

    let ctx = create_test_context_with_env(envs);
    let provider = ProfileCredentialProvider::new();

    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("ProfileCredentialProvider should not fail");

    assert!(
        cred.is_some(),
        "Should load credentials from AWS profile files"
    );
    let cred = cred.unwrap();
    assert!(!cred.access_key_id.is_empty());
    assert!(!cred.secret_access_key.is_empty());
}
