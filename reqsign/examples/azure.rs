use anyhow::Result;
use reqsign::azure;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Create a default signer for Azure Storage
    let signer = azure::default_signer();

    // Build a request
    let mut req = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://myaccount.blob.core.windows.net/mycontainer/myblob")
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
