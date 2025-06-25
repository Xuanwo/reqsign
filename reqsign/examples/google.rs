use anyhow::Result;
use reqsign::google::{DefaultCredentialProvider, RequestSigner};
use reqsign::{Context, DefaultContext, Signer};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Create a default context implementation
    let ctx_impl = DefaultContext::new();

    // Create a Context from the implementation
    let ctx = Context::new(ctx_impl.clone(), ctx_impl.clone()).with_env(ctx_impl.clone());

    // Create credential loader
    let loader = DefaultCredentialProvider::new();

    // Create request builder (for Google Cloud Storage)
    let builder = RequestSigner::new("storage.googleapis.com");

    // Create the signer
    let signer = Signer::new(ctx.clone(), loader, builder);

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

    // Execute the request - rebuild the request
    let signed_req = http::Request::from_parts(req, bytes::Bytes::new());
    let resp = ctx.http_send(signed_req).await?;
    println!("Response status: {}", resp.status());

    Ok(())
}
