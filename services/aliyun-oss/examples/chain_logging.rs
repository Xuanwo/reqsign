//! Example demonstrating credential chain logging for Aliyun OSS

use reqsign_aliyun_oss::{
    AssumeRoleWithOidcCredentialProvider, ConfigCredentialProvider, ProvideCredentialChain,
};
use reqsign_core::{Context, ProvideCredential};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logger with debug level
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .init();

    // Create context
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    // Create config that will likely not have credentials
    let config = Arc::new(reqsign_aliyun_oss::Config::default());

    // Create a chain with multiple providers
    let chain = ProvideCredentialChain::new()
        .push(ConfigCredentialProvider::new(config.clone()))
        .push(AssumeRoleWithOidcCredentialProvider::new(config));

    // Try to load credentials - this will show debug logs for each provider
    // Note: The debug output will include the full Debug representation of each provider,
    // which includes all configuration details. This is intentional for debugging purposes.
    println!("Attempting to load credentials from chain...\n");
    match chain.provide_credential(&ctx).await? {
        Some(cred) => println!("\nFound credential: {:?}", cred),
        None => println!("\nNo credential found in any provider"),
    }

    Ok(())
}
