mod config;
#[deprecated(
    since = "0.1.0",
    note = "Use EnvCredentialProvider or StaticCredentialProvider instead"
)]
pub use config::ConfigCredentialProvider;

mod env;
pub use env::EnvCredentialProvider;

mod static_;
pub use static_::StaticCredentialProvider;

mod config_file;
pub use config_file::ConfigFileCredentialProvider;

mod default;
pub use default::DefaultCredentialProvider;
