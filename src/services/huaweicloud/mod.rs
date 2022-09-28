//! Huawei Cloud signers
//! Currently only support Object Storage Service (OBS) singer.
//!
//! Use [`services::huaweicloud::obs::Signer`][crate::services::huaweicloud::obs::Signer]
pub mod obs;

mod constants;
mod loader;
mod subresource;
