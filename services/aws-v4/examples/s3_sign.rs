use anyhow::Result;
use reqsign_aws_v4::{Builder, Config, DefaultLoader};
use reqsign_core::{Context, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqwest::Client;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging for debugging
    env_logger::init();

    // Create HTTP client
    let client = Client::new();

    // Create context with Tokio file reader and reqwest HTTP client
    let ctx = Context::new(
        TokioFileRead,
        ReqwestHttpSend::new(client.clone()),
    );

    // Configure AWS credential loading
    // This will try multiple sources in order:
    // 1. Environment variables
    // 2. ~/.aws/credentials file
    // 3. IAM instance roles
    let config = Config::default().from_env(&ctx);

    // Create credential loader
    let loader = DefaultLoader::new(std::sync::Arc::new(config));

    // Create request builder for S3 in us-east-1
    let builder = Builder::new("s3", "us-east-1");

    // Create the signer
    let signer = Signer::new(ctx, loader, builder);

    // Example 1: List buckets
    println!("Example 1: Listing S3 buckets");
    let req = http::Request::get("https://s3.amazonaws.com/")
        .header("x-amz-content-sha256", reqsign_aws_v4::EMPTY_STRING_SHA256)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, body) = req.into_parts();
    
    // Sign the request
    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("Request signed successfully!");
            
            // Convert back to reqwest request and execute
            let req = http::Request::from_parts(parts, body).try_into()?;
            match client.execute(req).await {
                Ok(resp) => {
                    println!("Response status: {}", resp.status());
                    if resp.status().is_success() {
                        let text = resp.text().await?;
                        println!("First 500 chars of response:\n{}", &text[..500.min(text.len())]);
                    }
                }
                Err(e) => eprintln!("Request failed: {}", e),
            }
        }
        Err(e) => eprintln!("Failed to sign request: {}", e),
    }

    // Example 2: GET object (you'll need to change bucket/key to something you have access to)
    println!("\nExample 2: GET object from S3");
    let bucket = "my-test-bucket";
    let key = "test-file.txt";
    let url = format!("https://{}.s3.amazonaws.com/{}", bucket, key);
    
    let req = http::Request::get(&url)
        .header("x-amz-content-sha256", reqsign_aws_v4::EMPTY_STRING_SHA256)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, _body) = req.into_parts();
    
    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("GET request to {} signed successfully!", url);
            println!("Authorization header: {:?}", parts.headers.get("authorization"));
            println!("X-Amz-Date header: {:?}", parts.headers.get("x-amz-date"));
        }
        Err(e) => eprintln!("Failed to sign GET request: {}", e),
    }

    // Example 3: Sign with specific expiration (for pre-signed URLs)
    println!("\nExample 3: Sign with 1 hour expiration");
    let req = http::Request::get(&url)
        .header("x-amz-content-sha256", reqsign_aws_v4::EMPTY_STRING_SHA256)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, _body) = req.into_parts();
    
    match signer
        .sign(&mut parts, Some(std::time::Duration::from_secs(3600)))
        .await
    {
        Ok(_) => {
            println!("Request signed with 1 hour expiration!");
        }
        Err(e) => eprintln!("Failed to sign with expiration: {}", e),
    }

    Ok(())
}