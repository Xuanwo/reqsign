//! Example of using custom credential provider chain

use reqsign_aws_v4::{
    ConfigCredentialProvider, Credential, IMDSv2CredentialProvider, ProvideCredentialChain,
    RequestSigner,
};
use reqsign_core::{Context, ProvideCredential, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use std::sync::Arc;

/// A custom credential provider that always returns a fixed credential
#[derive(Debug)]
struct CustomCredentialProvider {
    access_key: String,
    secret_key: String,
}

#[async_trait::async_trait]
impl ProvideCredential for CustomCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        println!("Loading credential from custom provider");
        Ok(Some(Credential {
            access_key_id: self.access_key.clone(),
            secret_access_key: self.secret_key.clone(),
            session_token: None,
            expires_in: None,
        }))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Create context
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    // Create config
    let config = Arc::new(reqsign_aws_v4::Config::default());

    // Example 1: Create a custom chain with specific order
    println!("Example 1: Custom chain with specific order");
    let custom_chain = ProvideCredentialChain::new()
        .push(ConfigCredentialProvider::new(config.clone()))
        .push(CustomCredentialProvider {
            access_key: "custom_key".to_string(),
            secret_key: "custom_secret".to_string(),
        })
        .push(IMDSv2CredentialProvider::new(config.clone()));

    // Test the chain
    match custom_chain.provide_credential(&ctx).await? {
        Some(cred) => println!("Found credential: {:?}", cred),
        None => println!("No credential found"),
    }

    // Example 2: Create a chain that only uses local sources (no network calls)
    println!("\nExample 2: Local-only chain");
    let _local_chain =
        ProvideCredentialChain::new().push(ConfigCredentialProvider::new(config.clone()));

    // Example 3: Dynamic chain building
    println!("\nExample 3: Dynamic chain building");
    let mut dynamic_chain = ProvideCredentialChain::new();

    // Always add config provider
    dynamic_chain = dynamic_chain.push(ConfigCredentialProvider::new(config.clone()));

    // Conditionally add custom provider
    if std::env::var("USE_CUSTOM_PROVIDER").is_ok() {
        dynamic_chain = dynamic_chain.push(CustomCredentialProvider {
            access_key: "dynamic_key".to_string(),
            secret_key: "dynamic_secret".to_string(),
        });
    }

    // Conditionally add IMDS provider
    if !config.ec2_metadata_disabled {
        dynamic_chain = dynamic_chain.push(IMDSv2CredentialProvider::new(config.clone()));
    }

    // Use the dynamic chain (for demonstration)
    let _dynamic_chain = dynamic_chain;

    // Example 4: Using the chain with a signer
    println!("\nExample 4: Using chain with signer");
    let builder = RequestSigner::new("s3", "us-east-1");
    let signer = Signer::new(ctx.clone(), custom_chain, builder);

    // Create a sample request
    let mut req = http::Request::get("https://s3.amazonaws.com/mybucket/mykey")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    // This would sign the request if credentials are available
    match signer.sign(&mut req, None).await {
        Ok(_) => println!("Request signed successfully"),
        Err(e) => println!("Failed to sign request: {}", e),
    }

    Ok(())
}
