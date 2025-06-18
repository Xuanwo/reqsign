use anyhow::Result;
use reqsign_aws_v4::{Config, DefaultCredentialProvider, RequestSigner};
use reqsign_core::{Context, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqwest::Client;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging for debugging
    let _ = env_logger::builder().is_test(true).try_init();

    // Create HTTP client
    let client = Client::new();

    // Create context with Tokio file reader and reqwest HTTP client
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::new(client.clone()));

    // Configure AWS credential loading
    // For demo purposes, set demo credentials if none exist
    let mut config = Config::default();
    config = config.from_env(&ctx);

    // If no credentials are found, use demo credentials
    if config.access_key_id.is_none() {
        println!("No AWS credentials found, using demo credentials for example");
        config.access_key_id = Some("AKIAIOSFODNN7EXAMPLE".to_string());
        config.secret_access_key = Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string());
        config.region = Some("us-east-1".to_string());
    }

    // Create credential loader
    let loader = DefaultCredentialProvider::new(std::sync::Arc::new(config));

    // Create request builder for S3 in us-east-1
    let builder = RequestSigner::new("s3", "us-east-1");

    // Create the signer
    let signer = Signer::new(ctx, loader, builder);

    // Example 1: List buckets
    println!("Example 1: Listing S3 buckets");
    let req = http::Request::get("https://s3.amazonaws.com/")
        .header("x-amz-content-sha256", reqsign_aws_v4::EMPTY_STRING_SHA256)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    // Sign the request
    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("Request signed successfully!");

            // In demo mode, don't actually send the request
            println!("Demo mode: Not sending actual request to AWS");
            println!(
                "Authorization header: {:?}",
                parts.headers.get("authorization")
            );
            println!("X-Amz-Date header: {:?}", parts.headers.get("x-amz-date"));
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
            println!(
                "Authorization header: {:?}",
                parts.headers.get("authorization")
            );
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
