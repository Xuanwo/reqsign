use anyhow::Result;
use reqsign::azure::{DefaultCredentialProvider, RequestSigner};
use reqsign::{default_context, Signer};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Create a context with default implementations
    let ctx = default_context();

    // Create credential loader - will try multiple credential sources
    let loader = DefaultCredentialProvider::new();

    // Create request builder
    let builder = RequestSigner::new();

    // Create the signer
    let signer = Signer::new(ctx.clone(), loader, builder);

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

    // Execute the request - rebuild the request
    let signed_req = http::Request::from_parts(req, bytes::Bytes::new());
    let resp = ctx.http_send(signed_req).await?;
    println!("Response status: {}", resp.status());

    Ok(())
}
