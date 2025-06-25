//! Integration tests for ProvideCredentialChain with Tencent COS

use async_trait::async_trait;
use reqsign_core::ProvideCredentialChain;
use reqsign_core::{Context, ProvideCredential, Result};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqsign_tencent_cos::{Credential, EnvCredentialProvider};
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

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        let mut count = self.call_count.lock().unwrap();
        *count += 1;

        if self.return_credential {
            Ok(Some(Credential {
                secret_id: format!("{}_id", self.name),
                secret_key: format!("{}_key", self.name),
                security_token: None,
                expires_in: None,
            }))
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
    assert_eq!(cred.secret_id, "provider2_id");
    assert_eq!(cred.secret_key, "provider2_key");

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
            ("TENCENTCLOUD_SECRET_ID".to_string(), "test_id".to_string()),
            (
                "TENCENTCLOUD_SECRET_KEY".to_string(),
                "test_key".to_string(),
            ),
        ]),
    });

    // Create a chain with EnvCredentialProvider
    let chain = ProvideCredentialChain::new().push(EnvCredentialProvider::new());

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_some());

    let cred = result.unwrap();
    assert_eq!(cred.secret_id, "test_id");
    assert_eq!(cred.secret_key, "test_key");
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
    assert_eq!(cred.secret_id, "temp_id");
    assert_eq!(cred.secret_key, "temp_key");
    assert_eq!(cred.security_token, Some("security_token".to_string()));
}

/// Mock provider that returns credentials with security token
#[derive(Debug)]
struct SecurityTokenProvider;

#[async_trait]
impl ProvideCredential for SecurityTokenProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        Ok(Some(Credential {
            secret_id: "temp_id".to_string(),
            secret_key: "temp_key".to_string(),
            security_token: Some("security_token".to_string()),
            expires_in: Some(
                reqsign_core::time::now() + chrono::TimeDelta::try_hours(1).expect("in bounds"),
            ),
        }))
    }
}
