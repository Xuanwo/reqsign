use anyhow::Result;
use reqsign::aws::{DefaultCredentialProvider, RequestSigner};
use reqsign::{Context, DefaultContext, Signer};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Create a default context implementation
    let ctx_impl = DefaultContext::new();

    // Create a Context from the implementation
    let ctx = Context::new()
        .with_file_read(ctx_impl.clone())
        .with_http_send(ctx_impl.clone())
        .with_env(ctx_impl.clone());

    // Create credential loader
    let loader = DefaultCredentialProvider::new();

    // Create request builder for S3
    let builder = RequestSigner::new("s3", "us-east-1");

    // Create the signer
    let signer = Signer::new(ctx.clone(), loader, builder);

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

    // Execute the request - rebuild the request
    let signed_req = http::Request::from_parts(req, bytes::Bytes::new());
    let resp = ctx.http_send(signed_req).await?;
    println!("Response status: {}", resp.status());

    Ok(())
}
