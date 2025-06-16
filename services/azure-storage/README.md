# Azure Storage Signer

A Rust library for signing Azure Storage requests with support for multiple authentication methods.

## Features

- **Shared Key Authentication**: Sign requests using Azure Storage account name and key
- **SAS Token Authentication**: Use Shared Access Signature tokens for granular access control
- **Bearer Token Authentication**: OAuth-based authentication with Azure Active Directory
- **Multiple Credential Sources**: Load credentials from environment variables, configuration, IMDS, workload identity, and client secrets
- **Pre-signed URLs**: Generate query-string signed URLs with expiration times
- **Unified API**: Built on the `reqsign-core` framework for consistent experience across cloud providers

## Quick Start

### Basic Usage with Shared Key

```rust
use reqsign_azure_storage::{Builder, DefaultLoader};
use reqsign_core::{Context, Signer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create context (you'll need proper FileRead and HttpSend implementations)
    let ctx = Context::new(file_reader, http_sender);
    
    // Create loader with account credentials
    let loader = DefaultLoader::new()
        .with_account_key("myaccount", "base64_encoded_key");
    
    // Create builder and signer
    let builder = Builder::new();
    let signer = Signer::new(loader, builder);
    
    // Sign your request
    let mut req = http::Request::get("https://myaccount.blob.core.windows.net/container/blob")
        .body(reqwest::Body::default())?;
    
    signer.sign(&ctx, &mut req).await?;
    
    // Send the signed request...
    Ok(())
}
```

### Using Environment Variables

```rust
use reqsign_azure_storage::{Builder, DefaultLoader};
use reqsign_core::{Context, Signer};

// Set environment variables:
// AZBLOB_ACCOUNT_NAME=myaccount
// AZBLOB_ACCOUNT_KEY=base64_encoded_key

let ctx = Context::new(file_reader, http_sender);
let loader = DefaultLoader::new().from_env(&ctx);
let builder = Builder::new();
let signer = Signer::new(loader, builder);
```

### Using SAS Token

```rust
let loader = DefaultLoader::new()
    .with_sas_token("sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx&se=2022-01-01T11:00:14Z&...");
```

### Pre-signed URLs

```rust
use std::time::Duration;

// Generate a URL that's valid for 1 hour
signer.sign_query(&ctx, &mut req, Duration::from_secs(3600)).await?;
println!("Pre-signed URL: {}", req.uri());
```

## Authentication Methods

### 1. Shared Key Authentication

Uses the Azure Storage account name and access key to sign requests.

```rust
let loader = DefaultLoader::new()
    .with_account_key("account_name", "base64_encoded_key");
```

Environment variables:
- `AZBLOB_ACCOUNT_NAME` or `AZURE_STORAGE_ACCOUNT_NAME`
- `AZBLOB_ACCOUNT_KEY` or `AZURE_STORAGE_ACCOUNT_KEY`

### 2. SAS Token Authentication

Uses a Shared Access Signature token for limited access.

```rust
let loader = DefaultLoader::new()
    .with_sas_token("sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx&...");
```

Environment variables:
- `AZURE_STORAGE_SAS_TOKEN`

### 3. Bearer Token Authentication (OAuth)

Uses Azure Active Directory tokens for authentication.

#### Client Secret Flow
```rust
let loader = DefaultLoader::new()
    .with_client_secret("tenant_id", "client_id", "client_secret");
```

Environment variables:
- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID` 
- `AZURE_CLIENT_SECRET`

#### Workload Identity (Federated Credentials)
```rust
let loader = DefaultLoader::new()
    .with_workload_identity("tenant_id", "client_id", "/path/to/token/file");
```

Environment variables:
- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID`
- `AZURE_FEDERATED_TOKEN_FILE`

#### Managed Identity (IMDS)
```rust
let loader = DefaultLoader::new()
    .with_imds()
    .with_imds_client_id("client_id"); // For user-assigned identity
```

Environment variables:
- `AZURE_CLIENT_ID` (for user-assigned identity)
- `AZURE_OBJECT_ID` (alternative for user-assigned identity)
- `AZURE_MSI_RES_ID` (ARM resource ID for user-assigned identity)

## Credential Loading Priority

The `DefaultLoader` tries credential sources in this order:

1. **Configuration**: Explicitly set account key or SAS token
2. **Client Secret**: Service principal authentication
3. **Workload Identity**: Federated token authentication  
4. **IMDS**: Managed identity on Azure VMs/services

## Migration from v0.1

The library has been refactored to use the `reqsign-core` framework. The old API is still available but deprecated:

### Old API (Deprecated)
```rust
use reqsign_azure_storage::{Config, Loader, Signer};

let config = Config::default().from_env();
let loader = Loader::new(config);
let signer = Signer::new();

// Sign request
let cred = loader.load().await?;
signer.sign(&mut parts, &cred)?;
```

### New API (Recommended)
```rust
use reqsign_azure_storage::{Builder, DefaultLoader};
use reqsign_core::{Context, Signer};

let ctx = Context::new(file_reader, http_sender);
let loader = DefaultLoader::new().from_env(&ctx);
let builder = Builder::new();
let signer = Signer::new(loader, builder);

// Sign request
signer.sign(&ctx, &mut req).await?;
```

## Examples

See the `examples/` directory for complete working examples:

```bash
cargo run --example example
```

## Environment Variables Reference

| Variable | Description | Auth Method |
|----------|-------------|-------------|
| `AZBLOB_ACCOUNT_NAME` | Storage account name | Shared Key |
| `AZBLOB_ACCOUNT_KEY` | Storage account key | Shared Key |
| `AZURE_STORAGE_SAS_TOKEN` | SAS token | SAS |
| `AZURE_TENANT_ID` | Azure tenant ID | OAuth |
| `AZURE_CLIENT_ID` | Azure client ID | OAuth |
| `AZURE_CLIENT_SECRET` | Azure client secret | Client Secret |
| `AZURE_FEDERATED_TOKEN_FILE` | Path to federated token | Workload Identity |
| `AZURE_AUTHORITY_HOST` | OAuth authority host | OAuth |
| `AZURE_OBJECT_ID` | Object ID for managed identity | IMDS |
| `AZURE_MSI_RES_ID` | MSI resource ID | IMDS |
| `AZURE_MSI_ENDPOINT` | Custom IMDS endpoint | IMDS |
| `AZURE_MSI_SECRET` | MSI secret header | IMDS |

## License

This project is licensed under the Apache License 2.0.