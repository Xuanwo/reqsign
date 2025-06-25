//! AWS SigV4 signing implementation for reqsign.
//!
//! This crate provides AWS Signature Version 4 (SigV4) signing capabilities
//! for authenticating requests to AWS services like S3, DynamoDB, Lambda, and more.
//!
//! ## Overview
//!
//! AWS SigV4 is the authentication protocol used by most AWS services. This crate
//! implements the complete signing algorithm along with credential loading from
//! various sources including environment variables, credential files, IAM roles,
//! and more.
//!
//! ## Quick Start
//!
//! ```no_run
//! use reqsign_aws_v4::{RequestSigner, DefaultCredentialProvider};
//! use reqsign_core::{Context, Signer};
//! use reqsign_file_read_tokio::TokioFileRead;
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create context
//!     let ctx = Context::new(
//!         TokioFileRead::default(),
//!         ReqwestHttpSend::default(),
//!     );
//!
//!     // Create credential loader
//!     let loader = DefaultCredentialProvider::new(&ctx);
//!
//!     // Create request builder for S3
//!     let builder = RequestSigner::new("s3", "us-east-1");
//!
//!     // Create the signer
//!     let signer = Signer::new(ctx, loader, builder);
//!
//!     // Sign requests
//!     let mut req = http::Request::get("https://s3.amazonaws.com/mybucket/mykey")
//!         .body(())
//!         .unwrap()
//!         .into_parts()
//!         .0;
//!
//!     signer.sign(&mut req, None).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Credential Sources
//!
//! The crate supports loading credentials from multiple sources:
//!
//! 1. **Environment Variables**: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
//! 2. **Credential File**: `~/.aws/credentials`
//! 3. **IAM Roles**: For EC2 instances and ECS tasks
//! 4. **AssumeRole**: Via STS AssumeRole operations
//! 5. **WebIdentity**: For Kubernetes service accounts
//! 6. **SSO**: AWS SSO credentials
//!
//! ## Supported Services
//!
//! This implementation works with any AWS service that uses SigV4:
//!
//! - Amazon S3
//! - Amazon DynamoDB
//! - AWS Lambda
//! - Amazon SQS
//! - Amazon SNS
//! - And many more...
//!
//! ## Advanced Configuration
//!
//! ### Using Custom Credential Providers
//!
//! ```no_run
//! use reqsign_aws_v4::{EnvCredentialProvider, ProfileCredentialProvider};
//! use reqsign_core::ProvideCredentialChain;
//!
//! // Create a custom credential chain
//! let chain = ProvideCredentialChain::new()
//!     .push(EnvCredentialProvider::new())
//!     .push(ProfileCredentialProvider::new()
//!         .with_profile("production"));
//! ```
//!
//! ### Custom Credential Provider
//!
//! You can create custom credential providers by implementing the `ProvideCredential` trait:
//!
//! ```no_run
//! use reqsign_core::{ProvideCredential, Context, Result};
//! use async_trait::async_trait;
//!
//! # #[derive(Debug)]
//! # struct MyCredentialProvider;
//! # type Credential = reqsign_aws_v4::Credential;
//! #[async_trait]
//! impl ProvideCredential for MyCredentialProvider {
//!     type Credential = Credential;
//!     
//!     async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
//!         // Your custom credential loading logic
//!         Ok(None)
//!     }
//! }
//! ```
//!
//! ## Examples
//!
//! Check out the examples directory for more detailed usage:
//! - [S3 signing example](examples/s3_sign.rs)
//! - [DynamoDB signing example](examples/dynamodb_sign.rs)

mod constants;

mod credential;
pub use credential::Credential;
mod sign_request;
pub use sign_request::RequestSigner;
mod provide_credential;
pub use provide_credential::*;

pub const EMPTY_STRING_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
