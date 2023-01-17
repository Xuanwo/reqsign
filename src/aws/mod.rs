//! AWS service signer
//!
//! Only sigv4 has been supported.
pub mod config;
pub mod credential;
pub mod v4;

mod constants;
mod region;
