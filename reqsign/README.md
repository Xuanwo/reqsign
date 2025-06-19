# reqsign

Signing HTTP requests for AWS, Azure, Google, Huawei, Aliyun, Tencent and Oracle services.

## Features

This crate provides a unified interface for signing HTTP requests across multiple cloud providers:

- **AWS**: Signature V4 for AWS services
- **Azure**: Azure Storage services
- **Google**: Google Cloud services  
- **Aliyun**: Aliyun Object Storage Service (OSS)
- **Huawei Cloud**: Object Storage Service (OBS)
- **Tencent Cloud**: Cloud Object Storage (COS)
- **Oracle**: Oracle Cloud services

## Quick Start

Add `reqsign` to your `Cargo.toml`:

```toml
[dependencies]
reqsign = "0.17"
```

By default, this includes the `default-context` feature which provides a ready-to-use context implementation using `reqwest` and `tokio`.

To use specific services only:

```toml
[dependencies]
reqsign = { version = "0.17", default-features = false, features = ["aws", "default-context"] }
```

## Example

```rust
use anyhow::Result;
use reqsign::{AwsDefaultLoader, AwsV4Signer, DefaultContext};
use reqwest::Request;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a default context
    let ctx = DefaultContext::new();
    
    // Build and sign a request
    let req = Request::new(
        http::Method::GET,
        "https://s3.amazonaws.com/my-bucket/my-object".parse()?,
    );
    
    // Load credentials and create signer  
    let loader = AwsDefaultLoader::new(ctx.clone());
    let signer = AwsV4Signer::new("s3", "us-east-1");
    let (req, cred) = signer.sign(req, &ctx, loader).await?.into_parts();
    
    // Execute the signed request
    let resp = ctx.http_send(req).await?;
    println!("Response: {:?}", resp.status());
    
    Ok(())
}
```

## Feature Flags

- `default`: Enables `default-context`
- `default-context`: Provides a default context implementation using `reqwest` and `tokio`
- `aliyun`: Enable Aliyun OSS support
- `aws`: Enable AWS services support  
- `azure`: Enable Azure Storage support
- `google`: Enable Google Cloud support
- `huaweicloud`: Enable Huawei Cloud OBS support
- `oracle`: Enable Oracle Cloud support
- `tencent`: Enable Tencent COS support
- `full`: Enable all service features
- `custom-context`: For advanced users who want to implement their own context

## Custom Context

If you need custom HTTP client or file system implementations, disable the default features and implement the required traits:

```toml
[dependencies]
reqsign = { version = "0.17", default-features = false, features = ["aws", "custom-context"] }
```

Then implement the `Context`, `FileRead`, `HttpSend`, and `Env` traits for your custom context type.