use anyhow::Result;
use reqsign::google;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Create a default signer for Google Cloud Storage
    let signer = google::default_signer("storage.googleapis.com");

    // Build a request
    let mut req = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://storage.googleapis.com/my-bucket/my-object")
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
