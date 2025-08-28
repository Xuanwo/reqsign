#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

// Re-export core types
pub use reqsign_core::*;

// Context utilities
#[cfg(feature = "default-context")]
mod context;
#[cfg(feature = "default-context")]
pub use context::default_context;

// Service modules with convenience APIs
#[cfg(feature = "aliyun")]
pub mod aliyun;

#[cfg(feature = "aws")]
pub mod aws;

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "google")]
pub mod google;

#[cfg(feature = "huaweicloud")]
pub mod huaweicloud;

#[cfg(feature = "oracle")]
pub mod oracle;

#[cfg(feature = "tencent")]
pub mod tencent;
