//! Integration tests for ProvideCredentialChain with Huawei Cloud OBS

use async_trait::async_trait;
use reqsign_core::ProvideCredentialChain;
use reqsign_core::{Context, ProvideCredential};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqsign_huaweicloud_obs::{ConfigCredentialProvider, Credential};
use std::sync::Arc;

/// Mock provider that tracks how many times it was called
#[derive(Debug)]
struct CountingProvider {
    name: String,
    return_credential: bool,
    call_count: Arc<std::sync::Mutex<usize>>,
}

#[async_trait]
impl ProvideCredential for CountingProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> reqsign_core::Result<Option<Self::Credential>> {
        let mut count = self.call_count.lock().unwrap();
        *count += 1;

        if self.return_credential {
            Ok(Some(Credential::new(
                format!("{}_key", self.name),
                format!("{}_secret", self.name),
                None,
            )))
        } else {
            Ok(None)
        }
    }
}

#[tokio::test]
async fn test_chain_stops_at_first_success() {
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    let count1 = Arc::new(std::sync::Mutex::new(0));
    let count2 = Arc::new(std::sync::Mutex::new(0));
    let count3 = Arc::new(std::sync::Mutex::new(0));

    let chain = ProvideCredentialChain::new()
        .push(CountingProvider {
            name: "provider1".to_string(),
            return_credential: false,
            call_count: count1.clone(),
        })
        .push(CountingProvider {
            name: "provider2".to_string(),
            return_credential: true,
            call_count: count2.clone(),
        })
        .push(CountingProvider {
            name: "provider3".to_string(),
            return_credential: true,
            call_count: count3.clone(),
        });

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_some());

    let cred = result.unwrap();
    assert_eq!(cred.access_key_id, "provider2_key");
    assert_eq!(cred.secret_access_key, "provider2_secret");

    // Verify call counts
    assert_eq!(*count1.lock().unwrap(), 1);
    assert_eq!(*count2.lock().unwrap(), 1);
    assert_eq!(*count3.lock().unwrap(), 0); // Should not be called
}

#[tokio::test]
async fn test_chain_with_real_providers() {
    use reqsign_core::StaticEnv;
    use std::collections::HashMap;

    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
    let ctx = ctx.with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::from_iter([
            (
                "HUAWEI_CLOUD_ACCESS_KEY_ID".to_string(),
                "test_key".to_string(),
            ),
            (
                "HUAWEI_CLOUD_SECRET_ACCESS_KEY".to_string(),
                "test_secret".to_string(),
            ),
        ]),
    });

    let config = Arc::new(reqsign_huaweicloud_obs::Config::default());

    // Create a chain with only ConfigCredentialProvider
    let chain = ProvideCredentialChain::new().push(ConfigCredentialProvider::new(config));

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_some());

    let cred = result.unwrap();
    assert_eq!(cred.access_key_id, "test_key");
    assert_eq!(cred.secret_access_key, "test_secret");
}

#[tokio::test]
async fn test_empty_chain_returns_none() {
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());
    let chain: ProvideCredentialChain<Credential> = ProvideCredentialChain::new();

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_chain_all_providers_return_none() {
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    let count1 = Arc::new(std::sync::Mutex::new(0));
    let count2 = Arc::new(std::sync::Mutex::new(0));

    let chain = ProvideCredentialChain::new()
        .push(CountingProvider {
            name: "provider1".to_string(),
            return_credential: false,
            call_count: count1.clone(),
        })
        .push(CountingProvider {
            name: "provider2".to_string(),
            return_credential: false,
            call_count: count2.clone(),
        });

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_none());

    // Verify all providers were called
    assert_eq!(*count1.lock().unwrap(), 1);
    assert_eq!(*count2.lock().unwrap(), 1);
}

#[tokio::test]
async fn test_chain_with_security_token() {
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    let chain = ProvideCredentialChain::new().push(SecurityTokenProvider);

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_some());

    let cred = result.unwrap();
    assert_eq!(cred.access_key_id, "temp_key");
    assert_eq!(cred.secret_access_key, "temp_secret");
    assert_eq!(cred.security_token, Some("security_token".to_string()));
}

/// Mock provider that returns credentials with security token
#[derive(Debug)]
struct SecurityTokenProvider;

#[async_trait]
impl ProvideCredential for SecurityTokenProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> reqsign_core::Result<Option<Self::Credential>> {
        Ok(Some(Credential::new(
            "temp_key".to_string(),
            "temp_secret".to_string(),
            Some("security_token".to_string()),
        )))
    }
}
