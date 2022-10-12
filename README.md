# reqsign &emsp; [![Build Status]][actions] [![Latest Version]][crates.io] [![Crate Downloads]][crates.io]

[Build Status]: https://img.shields.io/github/workflow/status/Xuanwo/reqsign/CI/main
[actions]: https://github.com/Xuanwo/reqsign/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/reqsign.svg
[crates.io]: https://crates.io/crates/reqsign
[Crate Downloads]: https://img.shields.io/crates/d/reqsign.svg

Signing API requests without effort.

---

Most API is simple. But they could be complicated when they are hidden from complex abstraction. `reqsign` bring the simple API back: build, sign, send.

## Quick Start

```rust
use reqsign::AwsV4Signer;
use reqwest::{Client, Request, Url};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()>{
    // Signer will load region and credentials from environment by default.
    let signer = AwsV4Signer::builder().service("s3").build()?;
    // Construct request
    let url = Url::parse("https://s3.amazonaws.com/testbucket")?;
    let mut req = reqwest::Request::new(http::Method::GET, url);

    // Signing request with Signer
    signer.sign(&mut req)?;

    // Sending already signed request.
    let resp = Client::new().execute(req).await?;
    println!("resp got status: {}", resp.status());
    Ok(())
}
```

## Features

- Pure rust with minimal dependencies.
- Test again official SDK and services.
- Supported services
  - Aliyun OSS: `reqsign::AliyunOssSigner`
  - AWS services (SigV4): `reqsign::AwsV4Signer`
  - Azure Storage services: `reqsign::AzureStorageSigner`
  - Google services: `reqsign::GoogleSigner`
  - Huawei Cloud OBS: `reqsign::HuaweicloudObsSigner`

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
