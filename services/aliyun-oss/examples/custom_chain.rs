//! Example of using custom credential provider chain for Aliyun OSS

use reqsign_aliyun_oss::{
    AssumeRoleWithOidcCredentialProvider, ConfigCredentialProvider, Credential,
    ProvideCredentialChain, RequestSigner,
};
use reqsign_core::{Context, ProvideCredential, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use std::sync::Arc;

/// A custom credential provider that loads from a specific environment variable prefix
#[derive(Debug)]
struct CustomEnvCredentialProvider {
    prefix: String,
}

#[async_trait::async_trait]
impl ProvideCredential for CustomEnvCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> anyhow::Result<Option<Self::Credential>> {
        println!(
            "Loading credential from custom environment provider with prefix: {}",
            self.prefix
        );

        let access_key_id = std::env::var(format!("{}_ACCESS_KEY_ID", self.prefix)).ok();
        let access_key_secret = std::env::var(format!("{}_ACCESS_KEY_SECRET", self.prefix)).ok();
        let security_token = std::env::var(format!("{}_SECURITY_TOKEN", self.prefix)).ok();

        match (access_key_id, access_key_secret) {
            (Some(id), Some(secret)) => Ok(Some(Credential {
                access_key_id: id,
                access_key_secret: secret,
                security_token,
                expires_in: None,
            })),
            _ => Ok(None),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Create context
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    // Create config
    let config = Arc::new(reqsign_aliyun_oss::Config::default());

    // Example 1: Create a custom chain with specific order
    println!("Example 1: Custom chain with specific order");
    let custom_chain = ProvideCredentialChain::new()
        .push(ConfigCredentialProvider::new(config.clone()))
        .push(CustomEnvCredentialProvider {
            prefix: "MYAPP_ALIYUN".to_string(),
        })
        .push(AssumeRoleWithOidcCredentialProvider::new(config.clone()));

    // Test the chain
    match custom_chain.provide_credential(&ctx).await? {
        Some(cred) => println!("Found credential: {:?}", cred),
        None => println!("No credential found"),
    }

    // Example 2: Create a chain that only uses local sources (no network calls)
    println!("\nExample 2: Local-only chain");
    let _local_chain = ProvideCredentialChain::new()
        .push(ConfigCredentialProvider::new(config.clone()))
        .push(CustomEnvCredentialProvider {
            prefix: "LOCAL_ALIYUN".to_string(),
        });

    // Example 3: Dynamic chain building
    println!("\nExample 3: Dynamic chain building");
    let mut dynamic_chain = ProvideCredentialChain::new();

    // Always add config provider
    dynamic_chain = dynamic_chain.push(ConfigCredentialProvider::new(config.clone()));

    // Conditionally add custom provider
    if std::env::var("USE_CUSTOM_PROVIDER").is_ok() {
        dynamic_chain = dynamic_chain.push(CustomEnvCredentialProvider {
            prefix: "CUSTOM_ALIYUN".to_string(),
        });
    }

    // Conditionally add assume role provider
    if config.role_arn.is_some() {
        dynamic_chain =
            dynamic_chain.push(AssumeRoleWithOidcCredentialProvider::new(config.clone()));
    }

    // Store the final chain (could be used later)
    let _final_dynamic_chain = dynamic_chain;

    // Example 4: Using the chain with a signer
    println!("\nExample 4: Using chain with signer");
    let builder = RequestSigner::new("mybucket");
    // Use the first example chain for demonstration
    let signer = Signer::new(ctx.clone(), custom_chain, builder);

    // Create a sample request
    let mut req = http::Request::get("https://mybucket.oss-cn-beijing.aliyuncs.com/mykey.txt")
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
