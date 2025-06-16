//! Signing API requests without effort.

// Make sure all our public APIs have docs.
#![warn(missing_docs)]

pub mod hash;
pub mod time;
pub mod utils;

mod context;
pub use context::Context;
mod fs;
pub use fs::FileRead;
mod http;
pub use http::HttpSend;
mod env;
pub use env::Env;
pub use env::StaticEnv;

mod api;
pub use api::{SignRequest, Key, ProvideCredential};
mod request;
pub use request::{SigningMethod, SigningRequest};
mod signer;
pub use signer::Signer;
