//! Signers for huaweicloud obs service.

mod config;
pub use config::Config;

mod key;
pub use key::Credential;

mod build;
pub use build::Builder;

mod load;
pub use load::{ConfigLoader, DefaultLoader};

mod constants;
