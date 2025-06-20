use reqsign_core::Result;
use async_trait::async_trait;
use http::request::Parts;
use reqsign_core::{Context, ProvideCredential, SignRequest, Signer, SigningCredential};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use std::time::Duration;

// Define a custom credential type
#[derive(Clone, Debug)]
struct MyCredential {
    api_key: String,
    api_secret: String,
}

impl SigningCredential for MyCredential {
    fn is_valid(&self) -> bool {
        !self.api_key.is_empty() && !self.api_secret.is_empty()
    }
}

// Implement a credential loader that loads from environment
#[derive(Debug)]
struct MyCredentialLoader;

#[async_trait]
impl ProvideCredential for MyCredentialLoader {
    type Credential = MyCredential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Load credentials from environment variables
        let api_key = ctx.env_var("MY_API_KEY").unwrap_or_default();
        let api_secret = ctx.env_var("MY_API_SECRET").unwrap_or_default();

        // For demo purposes, use dummy credentials if none are provided
        if api_key.is_empty() || api_secret.is_empty() {
            println!("No credentials found in environment, using demo credentials");
            return Ok(Some(MyCredential {
                api_key: "demo-api-key".to_string(),
                api_secret: "demo-api-secret".to_string(),
            }));
        }

        Ok(Some(MyCredential {
            api_key,
            api_secret,
        }))
    }
}

// Implement a request builder
#[derive(Debug)]
struct MyRequestBuilder {
    _service_name: String,
}

#[async_trait]
impl SignRequest for MyRequestBuilder {
    type Credential = MyCredential;

    async fn sign_request(
        &self,
        _ctx: &Context,
        req: &mut Parts,
        credential: Option<&Self::Credential>,
        _expires_in: Option<Duration>,
    ) -> Result<()> {
        let cred = credential.ok_or_else(|| anyhow::anyhow!("No credential provided"))?;

        // Add required headers
        req.headers
            .insert("x-api-key", cred.api_key.parse().unwrap());

        // In a real implementation, you would calculate a signature here
        req.headers
            .insert("x-api-signature", "calculated-signature".parse().unwrap());

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create a context with default implementations
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::default());

    // Create the credential loader and request builder
    let loader = MyCredentialLoader;
    let builder = MyRequestBuilder {
        _service_name: "my-api".to_string(),
    };

    // Create the signer
    let signer = Signer::new(ctx, loader, builder);

    // Create a request to sign
    let mut parts = http::Request::builder()
        .method("GET")
        .uri("https://api.example.com/v1/users")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    // Sign the request
    match signer.sign(&mut parts, None).await {
        Ok(_) => {
            println!("Request signed successfully!");
            println!("Headers: {:?}", parts.headers);
        }
        Err(e) => {
            eprintln!("Failed to sign request: {}", e);
        }
    }

    Ok(())
}
