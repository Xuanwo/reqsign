mod assume_role;
pub use assume_role::AssumeRoleCredentialProvider;

mod assume_role_with_web_identity;
pub use assume_role_with_web_identity::AssumeRoleWithWebIdentityCredentialProvider;

mod cognito;
pub use cognito::CognitoIdentityCredentialProvider;

mod default;
pub use default::DefaultCredentialProvider;

mod ecs;
pub use ecs::ECSCredentialProvider;

mod env;
pub use env::EnvCredentialProvider;

mod imds;
pub use imds::IMDSv2CredentialProvider;

#[cfg(not(target_arch = "wasm32"))]
mod process;
#[cfg(not(target_arch = "wasm32"))]
pub use process::ProcessCredentialProvider;

mod profile;
pub use profile::ProfileCredentialProvider;

#[cfg(not(target_arch = "wasm32"))]
mod sso;
#[cfg(not(target_arch = "wasm32"))]
pub use sso::SSOCredentialProvider;

mod r#static;
pub use r#static::StaticCredentialProvider;

mod utils;
