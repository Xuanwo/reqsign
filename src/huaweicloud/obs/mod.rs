//! Signers for huaweicloud obs service.

mod signer;
pub use signer::Builder;
pub use signer::Signer;

mod credential;
mod subresource;
