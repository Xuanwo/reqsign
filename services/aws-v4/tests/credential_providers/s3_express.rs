use super::create_test_context;
use log::info;
use reqsign_aws_v4::{DefaultCredentialProvider, S3ExpressSessionProvider};
use reqsign_core::ProvideCredential;
use std::env;

#[tokio::test]
async fn test_s3_express_session_provider() {
    if env::var("REQSIGN_AWS_V4_TEST_S3_EXPRESS").unwrap_or_default() != "on" {
        info!("REQSIGN_AWS_V4_TEST_S3_EXPRESS not set, skipping");
        return;
    }

    let bucket = env::var("REQSIGN_AWS_V4_S3_EXPRESS_BUCKET")
        .expect("REQSIGN_AWS_V4_S3_EXPRESS_BUCKET must be set for S3 Express test");

    let ctx = create_test_context();
    let base_provider = DefaultCredentialProvider::new();
    let provider = S3ExpressSessionProvider::new(bucket, base_provider);

    let cred = provider
        .provide_credential(&ctx)
        .await
        .expect("S3ExpressSessionProvider should not fail");

    assert!(
        cred.is_some(),
        "S3ExpressSessionProvider should return credentials"
    );
    let cred = cred.unwrap();
    assert!(!cred.access_key_id.is_empty());
    assert!(!cred.secret_access_key.is_empty());
    assert!(
        cred.session_token.is_some(),
        "S3 Express session should include session token"
    );
    assert!(
        cred.expires_in.is_some(),
        "S3 Express session should have expiration"
    );
}
