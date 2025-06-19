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

```rust,ignore
use anyhow::Result;
use reqsign::aws::{Config, DefaultCredentialProvider, RequestSigner};
use reqsign::{Context, DefaultContext, Signer};

#[tokio::main]
async fn main() -> Result<()> {
    // Create a default context implementation
    let ctx_impl = DefaultContext::new();
    
    // Create a Context from the implementation
    let ctx = Context::new(ctx_impl.clone(), ctx_impl.clone()).with_env(ctx_impl.clone());
    
    // Configure AWS credential loading
    let config = Config::default();
    let loader = DefaultCredentialProvider::new(config.into());
    
    // Create signer for S3
    let builder = RequestSigner::new("s3", "us-east-1");
    let signer = Signer::new(ctx.clone(), loader, builder);
    
    // Build and sign a request
    let mut req = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://s3.amazonaws.com/my-bucket/my-object")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    
    signer.sign(&mut req, None).await?;
    
    // Execute the signed request
    let signed_req = http::Request::from_parts(req, bytes::Bytes::new());
    let resp = ctx.http_send(signed_req).await?;
    println!("Response status: {}", resp.status());
    
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