//! Azure Storage SharedKey support
//!
//! Use [`azure::storage::Signer`][crate::azure::storage::Signer]
mod storage;
pub use storage::*;

mod constants;
