mod config;
#[deprecated(
    since = "0.1.0",
    note = "Use StaticCredentialProvider or EnvCredentialProvider instead"
)]
#[allow(deprecated)]
pub use config::ConfigCredentialProvider;

mod default;
pub use default::DefaultCredentialProvider;

mod assume_role_with_web_identity;
pub use assume_role_with_web_identity::AssumeRoleWithWebIdentityCredentialProvider;

mod env;
pub use env::EnvCredentialProvider;

mod r#static;
pub use r#static::StaticCredentialProvider;
