# reqsign &emsp; [![Build Status]][actions] [![Latest Version]][crates.io] [![Crate Downloads]][crates.io]

[Build Status]: https://img.shields.io/github/actions/workflow/status/Xuanwo/reqsign/ci.yml?branch=main
[actions]: https://github.com/Xuanwo/reqsign/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/reqsign.svg
[crates.io]: https://crates.io/crates/reqsign
[Crate Downloads]: https://img.shields.io/crates/d/reqsign.svg

Signing API requests without effort.

---

Most API is simple. But they could be complicated when they are hidden from complex abstraction. `reqsign` bring the simple API back: build, sign, send.

## Quick Start

```rust
use anyhow::Result;
use reqsign_aws_v4::{Config, DefaultCredentialProvider, RequestSigner, EMPTY_STRING_SHA256};
use reqsign_core::{Context, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqwest::Client;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    // Create HTTP client and context
    let client = Client::new();
    let ctx = Context::new(TokioFileRead, ReqwestHttpSend::new(client.clone()));
    
    // Configure AWS credentials (loads from env by default)
    let config = Config::default().from_env(&ctx);
    let loader = DefaultCredentialProvider::new(Arc::new(config));
    
    // Create request signer for S3
    let builder = RequestSigner::new("s3", "us-east-1");
    let signer = Signer::new(ctx, loader, builder);
    
    // Construct and sign the request
    let req = http::Request::get("https://s3.amazonaws.com/testbucket")
        .header("x-amz-content-sha256", EMPTY_STRING_SHA256)
        .body(reqwest::Body::from(""))?;
    let (mut parts, body) = req.into_parts();
    
    // Sign the request
    signer.sign(&mut parts, None).await?;
    let req = http::Request::from_parts(parts, body).try_into()?;
    
    // Send the signed request
    let resp = client.execute(req).await?;
    println!("resp got status: {}", resp.status());
    Ok(())
}
```

## Features

- Pure rust with minimal dependencies.
- Test again official SDK and services.
- Supported services
  - Aliyun OSS: `reqsign-aliyun-oss`
  - AWS services (SigV4): `reqsign-aws-v4`
  - Azure Storage services: `reqsign-azure-storage`
  - Google services: `reqsign-google`
  - Huawei Cloud OBS: `reqsign-huaweicloud-obs`
  - Oracle Cloud: `reqsign-oracle`
  - Tencent COS: `reqsign-tencent-cos`

## Contributing

Check out the [CONTRIBUTING.md](./CONTRIBUTING.md) guide for more details on getting started with contributing to this project.

## Getting help

Submit [issues](https://github.com/Xuanwo/reqsign/issues/new/choose) for bug report or asking questions in [discussion](https://github.com/Xuanwo/reqsign/discussions/new?category=q-a).

## Acknowledge

Inspired a lot from:

- [aws-sigv4](https://crates.io/crates/aws-sigv4) for AWS SigV4 support.
- [azure_storage_blobs](https://crates.io/crates/azure_storage_blobs) for Azure Storage support.

#### License

<sup>
Licensed under <a href="./LICENSE">Apache License, Version 2.0</a>.
</sup>
