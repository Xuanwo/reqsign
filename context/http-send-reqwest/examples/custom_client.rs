use anyhow::Result;
use bytes::Bytes;
use reqsign_core::Context;
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqwest::Client;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a custom reqwest client with specific configuration
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(10)
        .user_agent("reqsign-example/1.0")
        .danger_accept_invalid_certs(false)
        .build()?;

    println!("Created custom HTTP client with:");
    println!("  - 30 second timeout");
    println!("  - Max 10 idle connections per host");
    println!("  - Custom user agent");

    // Create context with the custom client
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::new(client));

    // Test the HTTP client with a simple request
    let test_url = "https://httpbin.org/get";
    println!("\nTesting HTTP client with GET {test_url}");

    let req = http::Request::builder()
        .method("GET")
        .uri(test_url)
        .header("X-Test-Header", "reqsign-example")
        .body(Bytes::new())?;

    match ctx.http_send(req).await {
        Ok(resp) => {
            println!("Response status: {}", resp.status());
            println!("Response headers:");
            for (name, value) in resp.headers() {
                println!("  {name}: {value:?}");
            }

            let body = resp.body();
            if let Ok(text) = String::from_utf8(body.to_vec()) {
                println!("\nResponse body:");
                println!("{text}");
            }
        }
        Err(e) => {
            eprintln!("Request failed: {e}");
        }
    }

    // Demonstrate using the default client
    println!("\n--- Using default client ---");
    let default_ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    let req2 = http::Request::builder()
        .method("POST")
        .uri("https://httpbin.org/post")
        .header("Content-Type", "application/json")
        .body(Bytes::from(r#"{"message": "Hello from reqsign!"}"#))?;

    match default_ctx.http_send(req2).await {
        Ok(resp) => {
            println!("POST request successful!");
            println!("Response status: {}", resp.status());
        }
        Err(e) => {
            eprintln!("POST request failed: {e}");
        }
    }

    Ok(())
}
