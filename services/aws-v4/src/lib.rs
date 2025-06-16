//! AWS service signer

mod constants;

mod config;
pub use config::Config;
mod credential;
pub use credential::Credential;
mod build;
pub use build::Builder;
mod load;
pub use load::*;

pub const EMPTY_STRING_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
