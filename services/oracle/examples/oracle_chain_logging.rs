//! Example of using ProvideCredentialChain with logging to see credential resolution

use async_trait::async_trait;
use log::{debug, info};
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqsign_oracle::{ConfigCredentialProvider, Credential, DefaultCredentialProvider};
use std::sync::Arc;

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
                debug!("Loaded credential for tenancy: {}", cred.tenancy);
                debug!("User: {}", cred.user);
                debug!("Key file: {}", cred.key_file);
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
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    // Build a chain with logging
    let chain = ProvideCredentialChain::new()
        .push(LoggingProvider::new(
            "Config",
            ConfigCredentialProvider::new(Arc::new(reqsign_oracle::Config::default())),
        ))
        .push(LoggingProvider::new(
            "Default",
            DefaultCredentialProvider::new(reqsign_oracle::Config::default()),
        ));

    info!("Starting credential resolution...");

    match chain.provide_credential(&ctx).await? {
        Some(cred) => {
            info!("Successfully resolved credentials!");
            println!("Tenancy: {}", cred.tenancy);
            println!("User: {}", cred.user);
            println!("Key file: {}", cred.key_file);
            println!("Fingerprint: {}", cred.fingerprint);
        }
        None => {
            info!("No credentials found in any provider");
        }
    }

    Ok(())
}
