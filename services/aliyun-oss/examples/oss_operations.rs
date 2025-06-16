use anyhow::Result;
use reqsign_aliyun_oss::{Builder, Config, DefaultLoader};
use reqsign_core::{Context, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqwest::Client;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    // Create HTTP client
    let client = Client::new();

    // Create context
    let ctx = Context::new(
        TokioFileRead,
        ReqwestHttpSend::new(client.clone()),
    );

    // Configure Aliyun OSS credentials
    // This will try multiple sources:
    // 1. Environment variables (ALIBABA_CLOUD_ACCESS_KEY_ID, ALIBABA_CLOUD_ACCESS_KEY_SECRET)
    // 2. Aliyun CLI config file (~/.aliyun/config.json)
    // 3. ECS RAM role (if running on Aliyun ECS)
    let config = Config::default().from_env(&ctx);

    // Create credential loader
    let loader = DefaultLoader::new(std::sync::Arc::new(config));

    // Create request builder
    let bucket = "my-bucket"; // Replace with your bucket name
    let builder = Builder::new(bucket);

    // Create the signer
    let signer = Signer::new(ctx, loader, builder);

    // Example 1: List objects in a bucket
    println!("Example 1: List objects in bucket");
    let url = format!("https://{}.oss-cn-beijing.aliyuncs.com/", bucket);

    let req = http::Request::get(&url)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("List objects request signed successfully!");
            
            // Execute the request
            let req = http::Request::from_parts(parts, body).try_into()?;
            match client.execute(req).await {
                Ok(resp) => {
                    println!("Response status: {}", resp.status());
                    if resp.status().is_success() {
                        let text = resp.text().await?;
                        println!("Objects XML response preview:");
                        println!("{}", &text[..500.min(text.len())]);
                    }
                }
                Err(e) => eprintln!("Request failed: {}", e),
            }
        }
        Err(e) => eprintln!("Failed to sign request: {}", e),
    }

    // Example 2: Get object metadata
    println!("\nExample 2: Get object metadata");
    let object_key = "test-file.txt";
    let url = format!("https://{}.oss-cn-beijing.aliyuncs.com/{}", bucket, object_key);

    let req = http::Request::head(&url)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("Get object metadata request signed successfully!");
            println!("Authorization header: {:?}", parts.headers.get("authorization"));
            println!("Date header: {:?}", parts.headers.get("date"));
        }
        Err(e) => eprintln!("Failed to sign request: {}", e),
    }

    // Example 3: Upload an object
    println!("\nExample 3: Upload an object");
    let upload_content = b"Hello from reqsign to Aliyun OSS!";
    let upload_key = "hello-oss.txt";
    let url = format!("https://{}.oss-cn-beijing.aliyuncs.com/{}", bucket, upload_key);

    let req = http::Request::put(&url)
        .header("Content-Type", "text/plain")
        .header("Content-Length", upload_content.len().to_string())
        .body(reqwest::Body::from(upload_content.to_vec()))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("Upload object request signed successfully!");
            println!("The request is ready to upload '{}' to OSS", upload_key);
        }
        Err(e) => eprintln!("Failed to sign request: {}", e),
    }

    // Example 4: Delete an object
    println!("\nExample 4: Delete an object");
    let delete_key = "old-file.txt";
    let url = format!("https://{}.oss-cn-beijing.aliyuncs.com/{}", bucket, delete_key);

    let req = http::Request::delete(&url)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("Delete object request signed successfully!");
        }
        Err(e) => eprintln!("Failed to sign request: {}", e),
    }

    // Example 5: List objects with prefix
    println!("\nExample 5: List objects with prefix");
    let url = format!(
        "https://{}.oss-cn-beijing.aliyuncs.com/?prefix=photos/2024/",
        bucket
    );

    let req = http::Request::get(&url)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("List objects with prefix request signed successfully!");
        }
        Err(e) => eprintln!("Failed to sign request: {}", e),
    }

    // Example 6: Using internal endpoint (VPC)
    println!("\nExample 6: Using internal endpoint");
    let internal_url = format!(
        "https://{}.oss-cn-beijing-internal.aliyuncs.com/{}",
        bucket, object_key
    );

    let req = http::Request::get(&internal_url)
        .body(reqwest::Body::from(""))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("Internal endpoint request signed successfully!");
            println!("Use this when running within Aliyun VPC for better performance");
        }
        Err(e) => eprintln!("Failed to sign request: {}", e),
    }

    Ok(())
}