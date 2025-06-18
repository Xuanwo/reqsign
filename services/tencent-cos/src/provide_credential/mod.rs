mod config;
pub use config::ConfigCredentialProvider;

mod default;
pub use default::DefaultCredentialProvider;

mod assume_role_with_web_identity;
pub use assume_role_with_web_identity::AssumeRoleWithWebIdentityCredentialProvider;
