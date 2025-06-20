//! Integration tests for ProvideCredentialChain with Oracle Cloud Infrastructure

use async_trait::async_trait;
use reqsign_core::ProvideCredentialChain;
use reqsign_core::{Context, ProvideCredential, Result};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqsign_oracle::{ConfigCredentialProvider, Credential};
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
                tenancy: format!("{}_tenancy", self.name),
                user: format!("{}_user", self.name),
                key_file: format!("/path/to/{}_key.pem", self.name),
                fingerprint: format!("{}_fingerprint", self.name),
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
    assert_eq!(cred.tenancy, "provider2_tenancy");
    assert_eq!(cred.user, "provider2_user");

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
            ("OCI_TENANCY".to_string(), "test_tenancy".to_string()),
            ("OCI_USER".to_string(), "test_user".to_string()),
            ("OCI_KEY_FILE".to_string(), "/path/to/key.pem".to_string()),
            (
                "OCI_FINGERPRINT".to_string(),
                "test_fingerprint".to_string(),
            ),
        ]),
    });

    let config = Arc::new(reqsign_oracle::Config::default());

    // Create a chain with only ConfigCredentialProvider
    let chain = ProvideCredentialChain::new().push(ConfigCredentialProvider::new(config));

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_some());

    let cred = result.unwrap();
    assert_eq!(cred.tenancy, "test_tenancy");
    assert_eq!(cred.user, "test_user");
    assert_eq!(cred.key_file, "/path/to/key.pem");
    assert_eq!(cred.fingerprint, "test_fingerprint");
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
