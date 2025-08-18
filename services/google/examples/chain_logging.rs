//! Example of using ProvideCredentialChain with logging to see credential resolution

use async_trait::async_trait;
use log::{debug, info};
use reqsign_core::{Context, OsEnv, ProvideCredential, ProvideCredentialChain, Result};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_google::{Credential, DefaultCredentialProvider};
use reqsign_http_send_reqwest::ReqwestHttpSend;

/// Wrapper that logs when credentials are loaded
#[derive(Debug)]
struct LoggingProvider<P> {
    name: String,
    inner: P,
}

impl<P> LoggingProvider<P> {
    fn new(name: impl Into<String>, provider: P) -> Self {
        Self {
            name: name.into(),
            inner: provider,
        }
    }
}

#[async_trait]
impl<P> ProvideCredential for LoggingProvider<P>
where
    P: ProvideCredential<Credential = Credential> + Send + Sync,
{
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        info!("Attempting to load credentials from: {}", self.name);

        match self.inner.provide_credential(ctx).await {
            Ok(Some(cred)) => {
                info!("Successfully loaded credentials from: {}", self.name);
                if cred.has_service_account() {
                    debug!("Credential contains service account");
                }
                if cred.has_token() {
                    debug!("Credential contains token");
                }
                Ok(Some(cred))
            }
            Ok(None) => {
                info!("No credentials found in: {}", self.name);
                Ok(None)
            }
            Err(e) => {
                info!("Error loading credentials from {}: {:?}", self.name, e);
                Err(e)
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Create context
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    // Build a chain with logging
    // You can add different providers to see which one resolves first
    let chain = ProvideCredentialChain::new()
        .push(LoggingProvider::new(
            "Environment/Well-known (via Default)",
            DefaultCredentialProvider::new(),
        ))
        // Example: Add a static provider if you have credentials in memory
        // .push(LoggingProvider::new(
        //     "Static",
        //     StaticCredentialProvider::new(r#"{"type": "service_account", ...}"#),
        // ))
        ;

    info!("Starting credential resolution...");

    match chain.provide_credential(&ctx).await? {
        Some(cred) => {
            info!("Successfully resolved credentials!");
            if let Some(sa) = &cred.service_account {
                println!("Service Account: {}", sa.client_email);
            }
            if let Some(token) = &cred.token {
                println!(
                    "Token: {}...",
                    &token.access_token[..20.min(token.access_token.len())]
                );
                if let Some(expires_at) = token.expires_at {
                    println!("Expires at: {expires_at}");
                }
            }
        }
        None => {
            info!("No credentials found in any provider");
        }
    }

    Ok(())
}
