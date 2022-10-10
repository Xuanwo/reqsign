//! AWS service signer
//!
//! Only sigv4 has been supported.
pub mod v4;

mod config;
mod constants;
mod credential;
mod region;
