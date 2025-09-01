use anyhow::Result;
use reqsign_core::{Context, OsEnv};
use reqsign_file_read_tokio::TokioFileRead;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a context with Tokio file reader
    let ctx = Context::new().with_file_read(TokioFileRead).with_env(OsEnv);

    // Get the path from command line arguments or use a demo file
    let path = env::args().nth(1).unwrap_or_else(|| {
        // Create a temporary demo file for the example
        let demo_content =
            "[default]\naws_access_key_id = DEMO_KEY\naws_secret_access_key = DEMO_SECRET\n";
        if let Some(temp_dir) = std::env::temp_dir().to_str() {
            let demo_path = format!("{temp_dir}/reqsign_demo_credentials");
            let _ = std::fs::write(&demo_path, demo_content);
            return demo_path;
        }
        "demo_credentials".to_string()
    });

    println!("Attempting to read file: {path}");

    // Read the file asynchronously
    match ctx.file_read(&path).await {
        Ok(content) => {
            println!("Successfully read {} bytes from {}", content.len(), path);

            // Try to parse as UTF-8 and show a preview
            if let Ok(text) = String::from_utf8(content.clone()) {
                let preview: String = text.lines().take(5).collect::<Vec<_>>().join("\n");
                println!("\nFirst few lines:");
                println!("{preview}");
                if text.lines().count() > 5 {
                    println!("... ({} more lines)", text.lines().count() - 5);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read file: {e}");
            eprintln!("Make sure the file exists and you have permission to read it.");
        }
    }

    Ok(())
}
