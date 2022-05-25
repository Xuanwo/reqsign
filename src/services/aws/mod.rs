//! AWS service signer
//!
//! Only sigv4 has been supported.
pub mod loader;
pub mod v4;

mod constants;
mod credential;
