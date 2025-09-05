mod assume_role_with_oidc;
pub use assume_role_with_oidc::AssumeRoleWithOidcCredentialProvider;

mod default;
pub use default::{DefaultCredentialProvider, DefaultCredentialProviderBuilder};

mod env;
pub use env::EnvCredentialProvider;

mod r#static;
pub use r#static::StaticCredentialProvider;
