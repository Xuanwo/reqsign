//! Azure Storage signing implementation for reqsign.
//!
//! This crate provides comprehensive signing support for Azure Storage services
//! including Blob Storage, File Storage, Queue Storage, and Table Storage.
//!
//! ## Overview
//!
//! Azure Storage supports multiple authentication methods, and this crate
//! implements all major ones:
//!
//! - **Shared Key**: Using storage account access keys
//! - **SAS Token**: Pre-generated Shared Access Signature tokens
//! - **Bearer Token**: OAuth2/Azure AD authentication
//!
//! ## Quick Start
//!
//! ```no_run
//! use anyhow::Result;
//! use reqsign_azure_storage::{Config, DefaultCredentialProvider, RequestSigner};
//! use reqsign_core::{Context, Signer};
//! use reqsign_file_read_tokio::TokioFileRead;
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//! use reqwest::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Create context
//!     let ctx = Context::new(
//!         TokioFileRead::default(),
//!         ReqwestHttpSend::default()
//!     );
//!
//!     // Create credential loader (will try multiple methods)
//!     let loader = DefaultCredentialProvider::new();
//!
//!     // Create request builder
//!     let builder = RequestSigner::new();
//!
//!     // Create the signer
//!     let signer = Signer::new(ctx, loader, builder);
//!
//!     // Sign requests
//!     let mut req = http::Request::get("https://mystorageaccount.blob.core.windows.net/container/blob")
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
//! # For Shared Key authentication
//! export AZURE_STORAGE_ACCOUNT_NAME=mystorageaccount
//! export AZURE_STORAGE_ACCOUNT_KEY=base64key
//!
//! # For SAS Token authentication
//! export AZURE_STORAGE_SAS_TOKEN=sv=2021-06-08&ss=b&srt=sco...
//!
//! # For Azure AD authentication
//! export AZURE_CLIENT_ID=client-id
//! export AZURE_CLIENT_SECRET=client-secret
//! export AZURE_TENANT_ID=tenant-id
//! ```
//!
//! ### Managed Identity
//!
//! When running on Azure services (VMs, App Service, AKS), the crate
//! automatically uses managed identity:
//!
//! ```no_run
//! use reqsign_azure_storage::{Config, DefaultCredentialProvider};
//!
//! // Create loader that will try managed identity
//! let loader = DefaultCredentialProvider::new();
//! ```
//!
//! ## Storage Services
//!
//! ### Blob Storage
//!
//! ```no_run
//! # use http::Request;
//! // List containers
//! let req = Request::get("https://account.blob.core.windows.net/?comp=list")
//!     .body(())
//!     .unwrap();
//!
//! // Get blob
//! let req = Request::get("https://account.blob.core.windows.net/container/blob.txt")
//!     .body(())
//!     .unwrap();
//! ```
//!
//! ### File Storage
//!
//! ```no_run
//! # use http::Request;
//! // List shares
//! let req = Request::get("https://account.file.core.windows.net/?comp=list")
//!     .body(())
//!     .unwrap();
//! ```
//!
//! ## Advanced Features
//!
//! ### Account SAS Generation
//!
//! Generate SAS tokens for delegated access:
//!
//! ```ignore
//! // Account SAS is not yet exposed in the public API
//! // This is planned for future releases
//! ```
//!
//! ### Custom Configuration
//!
//! ```no_run
//! use reqsign_azure_storage::Config;
//!
//! let config = Config::default()
//!     .with_account_name("mystorageaccount")
//!     .with_account_key("base64key")
//!     .with_sas_token("sv=2021-06-08...")
//!     .with_client_id("azure-ad-client-id")
//!     .with_authority_host("https://login.microsoftonline.com");
//! ```
//!
//! ## Examples
//!
//! Check out the examples directory for more detailed usage:
//! - [Blob storage operations](examples/blob_storage.rs)
//! - [SAS token generation](examples/sas_token.rs)

mod account_sas;
mod constants;

mod config;
pub use config::Config;

mod credential;
pub use credential::Credential;

mod sign_request;
pub use sign_request::RequestSigner;

mod provide_credential;
pub use provide_credential::*;
