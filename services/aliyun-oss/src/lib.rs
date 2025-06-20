//! Aliyun OSS signing implementation for reqsign.
//!
//! This crate provides signing support for Alibaba Cloud Object Storage Service (OSS),
//! enabling secure authentication for all OSS operations.
//!
//! ## Overview
//!
//! Aliyun OSS uses a custom signing algorithm based on HMAC-SHA1. This crate implements
//! the complete signing process along with credential loading from various sources
//! including environment variables, configuration files, and STS tokens.
//!
//! ## Quick Start
//!
//! ```no_run
//! use reqsign_aliyun_oss::{RequestSigner, Config, DefaultCredentialProvider};
//! use reqsign_core::{Context, Signer};
//! use reqsign_file_read_tokio::TokioFileRead;
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Create context
//!     let ctx = Context::new(
//!         TokioFileRead::default(),
//!         ReqwestHttpSend::default(),
//!     );
//!
//!     // Configure Aliyun OSS credentials
//!     let mut config = Config::default();
//!     config.access_key_id = Some("your-access-key-id".to_string());
//!     config.access_key_secret = Some("your-access-key-secret".to_string());
//!
//!     // Create credential loader
//!     let loader = DefaultCredentialProvider::new(config.into());
//!
//!     // Create request builder
//!     let builder = RequestSigner::new("bucket");
//!
//!     // Create the signer
//!     let signer = Signer::new(ctx, loader, builder);
//!
//!     // Sign requests
//!     let mut req = http::Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
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
//! ### Environment Variables
//!
//! ```bash
//! export ALIBABA_CLOUD_ACCESS_KEY_ID=your-access-key-id
//! export ALIBABA_CLOUD_ACCESS_KEY_SECRET=your-access-key-secret
//! export ALIBABA_CLOUD_SECURITY_TOKEN=your-sts-token  # Optional, for STS
//! ```
//!
//! ### Configuration File
//!
//! The crate can load credentials from the Aliyun CLI configuration file
//! (typically `~/.aliyun/config.json`).
//!
//! ### ECS RAM Role
//!
//! When running on Alibaba Cloud ECS instances with RAM roles attached,
//! credentials are automatically obtained from the metadata service.
//!
//! ## OSS Operations
//!
//! ### Object Operations
//!
//! ```no_run
//! # use http::Request;
//! // Get object
//! let req = Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
//!     .body(())
//!     .unwrap();
//!
//! // Put object
//! let req = Request::put("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
//!     .header("Content-Type", "text/plain")
//!     .body(b"Hello, OSS!")
//!     .unwrap();
//!
//! // Delete object
//! let req = Request::delete("https://bucket.oss-cn-beijing.aliyuncs.com/object.txt")
//!     .body(())
//!     .unwrap();
//! ```
//!
//! ### Bucket Operations
//!
//! ```no_run
//! # use http::Request;
//! // List objects
//! let req = Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/?prefix=photos/")
//!     .body(())
//!     .unwrap();
//!
//! // Get bucket info
//! let req = Request::get("https://bucket.oss-cn-beijing.aliyuncs.com/?bucketInfo")
//!     .body(())
//!     .unwrap();
//! ```
//!
//! ## Advanced Features
//!
//! ### STS AssumeRole
//!
//! ```no_run
//! use reqsign_aliyun_oss::{Config, AssumeRoleWithOidcCredentialProvider};
//!
//! let mut config = Config::default();
//! config.role_arn = Some("acs:ram::123456789012:role/MyRole".to_string());
//! config.oidc_provider_arn = Some("acs:ram::123456789012:oidc-provider/MyProvider".to_string());
//! config.oidc_token_file = Some("/var/run/secrets/token".to_string());
//!
//! let loader = AssumeRoleWithOidcCredentialProvider::new(config.into());
//! ```
//!
//! ### Custom Endpoints
//!
//! ```no_run
//! # use http::Request;
//! // Internal endpoint (VPC)
//! let req = Request::get("https://bucket.oss-cn-beijing-internal.aliyuncs.com/object.txt")
//!     .body(())
//!     .unwrap();
//!
//! // Accelerate endpoint
//! let req = Request::get("https://bucket.oss-accelerate.aliyuncs.com/object.txt")
//!     .body(())
//!     .unwrap();
//! ```
//!
//! ## Examples
//!
//! Check out the examples directory:
//! - [Basic OSS operations](examples/oss_operations.rs)
//! - [STS authentication](examples/sts_auth.rs)

mod constants;

mod config;
pub use config::Config;

mod credential;
pub use credential::Credential;

mod sign_request;
pub use sign_request::RequestSigner;

mod provide_credential;
pub use provide_credential::*;
