use anyhow::Result;
use reqsign::azure::{DefaultCredentialProvider, RequestSigner};
use reqsign::{Context, DefaultContext, Signer};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Create a default context implementation
    let ctx_impl = DefaultContext::new();

    // Create a Context from the implementation
    let ctx = Context::new(ctx_impl.clone(), ctx_impl.clone()).with_env(ctx_impl.clone());

    // Create credential loader - will try multiple credential sources
    let loader =
        DefaultCredentialProvider::new().with_account_key("myaccount", "base64-encoded-key"); // Optional: set account key

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
