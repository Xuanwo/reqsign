use anyhow::Result;
use reqsign::aws;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Create a default signer for S3 in us-east-1
    let signer = aws::default_signer("s3", "us-east-1");

    // Build a request
    let mut req = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://s3.amazonaws.com/my-bucket/my-object")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    // Sign the request
    signer.sign(&mut req, None).await?;

    // Execute the request would require rebuilding with body
    // In real usage, you'd use your HTTP client here
    println!("Request signed successfully!");

    Ok(())
}
