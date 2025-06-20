//! Example demonstrating credential chain logging

use reqsign_aws_v4::{
    ConfigCredentialProvider, IMDSv2CredentialProvider, ProvideCredentialChain,
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
    let config = Arc::new(reqsign_aws_v4::Config {
        ec2_metadata_disabled: true, // Disable IMDS to avoid network calls
        ..Default::default()
    });

    // Create a chain with multiple providers
    let chain = ProvideCredentialChain::new()
        .push(ConfigCredentialProvider::new(config.clone()))
        .push(IMDSv2CredentialProvider::new(config));

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