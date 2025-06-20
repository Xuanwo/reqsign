//! Integration tests for ProvideCredentialChain with Azure Storage

use async_trait::async_trait;
use reqsign_azure_storage::{ConfigCredentialProvider, Credential};
use reqsign_core::ProvideCredentialChain;
use reqsign_core::{Context, ProvideCredential};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use std::sync::Arc;

/// Mock provider that tracks how many times it was called
#[derive(Debug)]
struct CountingProvider {
    _name: String,
    return_credential: Option<Credential>,
    call_count: Arc<std::sync::Mutex<usize>>,
}

#[async_trait]
impl ProvideCredential for CountingProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        let mut count = self.call_count.lock().unwrap();
        *count += 1;

        Ok(self.return_credential.clone())
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
            _name: "provider1".to_string(),
            return_credential: None,
            call_count: count1.clone(),
        })
        .push(CountingProvider {
            _name: "provider2".to_string(),
            return_credential: Some(Credential::SharedKey {
                account_name: "testaccount".to_string(),
                account_key: "dGVzdGtleQ==".to_string(),
            }),
            call_count: count2.clone(),
        })
        .push(CountingProvider {
            _name: "provider3".to_string(),
            return_credential: Some(Credential::SasToken {
                token: "sv=2021-01-01&ss=b".to_string(),
            }),
            call_count: count3.clone(),
        });

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_some());

    let cred = result.unwrap();
    match cred {
        Credential::SharedKey {
            account_name,
            account_key,
        } => {
            assert_eq!(account_name, "testaccount");
            assert_eq!(account_key, "dGVzdGtleQ==");
        }
        _ => panic!("Expected SharedKey credential"),
    }

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
                "AZURE_STORAGE_ACCOUNT_NAME".to_string(),
                "testaccount".to_string(),
            ),
            (
                "AZURE_STORAGE_ACCOUNT_KEY".to_string(),
                "dGVzdGtleQ==".to_string(),
            ),
        ]),
    });

    // Create a chain with only ConfigCredentialProvider
    let chain = ProvideCredentialChain::new().push(
        ConfigCredentialProvider::new()
            .with_account_name("testaccount")
            .with_account_key("dGVzdGtleQ=="),
    );

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_some());

    let cred = result.unwrap();
    match cred {
        Credential::SharedKey {
            account_name,
            account_key,
        } => {
            assert_eq!(account_name, "testaccount");
            assert_eq!(account_key, "dGVzdGtleQ==");
        }
        _ => panic!("Expected SharedKey credential"),
    }
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
            _name: "provider1".to_string(),
            return_credential: None,
            call_count: count1.clone(),
        })
        .push(CountingProvider {
            _name: "provider2".to_string(),
            return_credential: None,
            call_count: count2.clone(),
        });

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_none());

    // Verify all providers were called
    assert_eq!(*count1.lock().unwrap(), 1);
    assert_eq!(*count2.lock().unwrap(), 1);
}

#[tokio::test]
async fn test_credential_validity_check() {
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    // Create an expired bearer token credential
    let expired_cred = Credential::BearerToken {
        token: "expired_token".to_string(),
        expires_in: None,
    };

    // Create a valid shared key credential
    let valid_cred = Credential::SharedKey {
        account_name: "testaccount".to_string(),
        account_key: "dGVzdGtleQ==".to_string(),
    };

    let chain = ProvideCredentialChain::new()
        .push(CountingProvider {
            _name: "expired_provider".to_string(),
            return_credential: Some(expired_cred),
            call_count: Arc::new(std::sync::Mutex::new(0)),
        })
        .push(CountingProvider {
            _name: "valid_provider".to_string(),
            return_credential: Some(valid_cred),
            call_count: Arc::new(std::sync::Mutex::new(0)),
        });

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_some());

    // Should get the first credential even if it might be expired
    // The chain doesn't validate credentials, just returns the first one found
    match result.unwrap() {
        Credential::BearerToken { token, .. } => {
            assert_eq!(token, "expired_token");
        }
        _ => panic!("Expected BearerToken credential"),
    }
}
