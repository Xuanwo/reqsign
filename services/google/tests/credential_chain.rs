//! Integration tests for ProvideCredentialChain with Google Cloud

use async_trait::async_trait;
use reqsign_core::ProvideCredentialChain;
use reqsign_core::{Context, OsEnv, ProvideCredential, Result};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_google::{Credential, DefaultCredentialProvider, ServiceAccount, Token};
use reqsign_http_send_reqwest::ReqwestHttpSend;
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
            // Return a credential with both service account and token for testing
            Ok(Some(Credential {
                service_account: Some(ServiceAccount {
                    private_key: format!("{}_private_key", self.name),
                    client_email: format!("{}@example.iam.gserviceaccount.com", self.name),
                }),
                token: Some(Token {
                    access_token: format!("{}_token", self.name),
                    expires_at: Some(
                        reqsign_core::time::now()
                            + chrono::TimeDelta::try_hours(1).expect("in bounds"),
                    ),
                }),
            }))
        } else {
            Ok(None)
        }
    }
}

#[tokio::test]
async fn test_chain_stops_at_first_success() {
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

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
    assert!(cred.has_service_account());
    assert!(cred.has_token());
    let sa = cred.service_account.as_ref().unwrap();
    assert_eq!(sa.client_email, "provider2@example.iam.gserviceaccount.com");
    let token = cred.token.as_ref().unwrap();
    assert_eq!(token.access_token, "provider2_token");

    // Verify call counts
    assert_eq!(*count1.lock().unwrap(), 1);
    assert_eq!(*count2.lock().unwrap(), 1);
    assert_eq!(*count3.lock().unwrap(), 0); // Should not be called
}

#[tokio::test]
async fn test_chain_with_real_providers() {
    use reqsign_core::StaticEnv;
    use std::collections::HashMap;
    use std::env;

    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);
    let ctx = ctx.with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::from_iter([(
            "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
            format!(
                "{}/testdata/test_credential.json",
                env::current_dir()
                    .expect("current_dir must exist")
                    .to_string_lossy()
            ),
        )]),
    });

    // Create a chain with DefaultCredentialProvider
    let chain = ProvideCredentialChain::new().push(DefaultCredentialProvider::new());

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_some());

    let cred = result.unwrap();
    assert!(cred.has_service_account());
    let sa = cred.service_account.as_ref().unwrap();
    assert_eq!(sa.client_email, "test-234@test.iam.gserviceaccount.com");
}

#[tokio::test]
async fn test_empty_chain_returns_none() {
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);
    let chain: ProvideCredentialChain<Credential> = ProvideCredentialChain::new();

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_chain_all_providers_return_none() {
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

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
async fn test_chain_with_token_credential() {
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let chain = ProvideCredentialChain::new().push(TokenProvider { return_valid: true });

    let result = chain.provide_credential(&ctx).await.unwrap();
    assert!(result.is_some());

    let cred = result.unwrap();
    assert!(cred.has_token());
    assert!(cred.has_valid_token());
}

/// Mock provider that returns token credentials
#[derive(Debug)]
struct TokenProvider {
    return_valid: bool,
}

#[async_trait]
impl ProvideCredential for TokenProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        if self.return_valid {
            let expires_at =
                reqsign_core::time::now() + chrono::TimeDelta::try_hours(1).expect("in bounds");
            Ok(Some(Credential::with_token(Token {
                access_token: "test_token".to_string(),
                expires_at: Some(expires_at),
            })))
        } else {
            Ok(None)
        }
    }
}
