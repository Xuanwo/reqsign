use anyhow::Result;
use reqsign_aws_v4::{Builder, Config, DefaultLoader};
use reqsign_core::{Context, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqwest::Client;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    // Create HTTP client
    let client = Client::new();

    // Create context
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::new(client.clone()));

    // Configure AWS credentials
    let mut config = Config::default();
    config = config.from_env(&ctx);
    config.region = Some("us-east-1".to_string());

    // Create credential loader
    let loader = DefaultLoader::new(std::sync::Arc::new(config));

    // Create request builder for DynamoDB
    let builder = Builder::new("dynamodb", "us-east-1");

    // Create the signer
    let signer = Signer::new(ctx, loader, builder);

    // Example 1: List tables
    println!("Example 1: Listing DynamoDB tables");

    let list_tables_body = json!({});
    let body_bytes = serde_json::to_vec(&list_tables_body)?;

    let req = http::Request::post("https://dynamodb.us-east-1.amazonaws.com/")
        .header("content-type", "application/x-amz-json-1.0")
        .header("x-amz-target", "DynamoDB_20120810.ListTables")
        .header(
            "x-amz-content-sha256",
            &reqsign_core::hash::hex_sha256(&body_bytes),
        )
        .body(reqwest::Body::from(body_bytes))
        .unwrap();

    let (mut parts, body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("ListTables request signed successfully!");

            // Execute the request
            let req = http::Request::from_parts(parts, body).try_into()?;
            match client.execute(req).await {
                Ok(resp) => {
                    println!("Response status: {}", resp.status());
                    if resp.status().is_success() {
                        let json: serde_json::Value = resp.json().await?;
                        println!("Tables: {}", serde_json::to_string_pretty(&json)?);
                    } else {
                        let text = resp.text().await?;
                        eprintln!("Error response: {}", text);
                    }
                }
                Err(e) => eprintln!("Request failed: {}", e),
            }
        }
        Err(e) => eprintln!("Failed to sign request: {}", e),
    }

    // Example 2: Describe a specific table
    println!("\nExample 2: Describe a table");

    let describe_table_body = json!({
        "TableName": "MyTestTable"
    });
    let body_bytes = serde_json::to_vec(&describe_table_body)?;

    let req = http::Request::post("https://dynamodb.us-east-1.amazonaws.com/")
        .header("content-type", "application/x-amz-json-1.0")
        .header("x-amz-target", "DynamoDB_20120810.DescribeTable")
        .header(
            "x-amz-content-sha256",
            &reqsign_core::hash::hex_sha256(&body_bytes),
        )
        .body(reqwest::Body::from(body_bytes))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("DescribeTable request signed successfully!");
            println!(
                "Authorization header: {:?}",
                parts.headers.get("authorization")
            );
        }
        Err(e) => eprintln!("Failed to sign request: {}", e),
    }

    // Example 3: Put item (write operation)
    println!("\nExample 3: Put item to DynamoDB");

    let put_item_body = json!({
        "TableName": "MyTestTable",
        "Item": {
            "id": {"S": "test-123"},
            "name": {"S": "Test Item"},
            "count": {"N": "42"}
        }
    });
    let body_bytes = serde_json::to_vec(&put_item_body)?;

    let req = http::Request::post("https://dynamodb.us-east-1.amazonaws.com/")
        .header("content-type", "application/x-amz-json-1.0")
        .header("x-amz-target", "DynamoDB_20120810.PutItem")
        .header(
            "x-amz-content-sha256",
            &reqsign_core::hash::hex_sha256(&body_bytes),
        )
        .body(reqwest::Body::from(body_bytes))
        .unwrap();

    let (mut parts, _body) = req.into_parts();

    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("PutItem request signed successfully!");
            println!("The request is ready to be sent to DynamoDB");
        }
        Err(e) => eprintln!("Failed to sign request: {}", e),
    }

    Ok(())
}
