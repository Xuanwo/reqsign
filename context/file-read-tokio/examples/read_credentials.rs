use anyhow::Result;
use reqsign_core::Context;
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a context with Tokio file reader
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    // Get the path from command line arguments or use a default
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "~/.aws/credentials".to_string());

    println!("Attempting to read file: {}", path);

    // Read the file asynchronously
    match ctx.file_read(&path).await {
        Ok(content) => {
            println!("Successfully read {} bytes from {}", content.len(), path);
            
            // Try to parse as UTF-8 and show a preview
            if let Ok(text) = String::from_utf8(content.clone()) {
                let preview: String = text.lines().take(5).collect::<Vec<_>>().join("\n");
                println!("\nFirst few lines:");
                println!("{}", preview);
                if text.lines().count() > 5 {
                    println!("... ({} more lines)", text.lines().count() - 5);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read file: {}", e);
            eprintln!("Make sure the file exists and you have permission to read it.");
        }
    }

    Ok(())
}