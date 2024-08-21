//! Huawei Cloud signers
//! Currently only support Object Storage Service (OBS) singer.
//!
//! Use [`huaweicloud::obs::Signer`][crate::huaweicloud::obs::Signer]
mod obs;
pub use obs::*;

mod constants;
