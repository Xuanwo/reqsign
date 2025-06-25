mod config;
#[deprecated(
    since = "0.1.0",
    note = "Use StaticCredentialProvider or EnvCredentialProvider instead"
)]
#[allow(deprecated)]
pub use config::ConfigCredentialProvider;

mod default;
pub use default::DefaultCredentialProvider;

mod env;
pub use env::EnvCredentialProvider;

mod r#static;
pub use r#static::StaticCredentialProvider;
