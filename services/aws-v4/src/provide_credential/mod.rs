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

mod process;
pub use process::ProcessCredentialProvider;

mod profile;
pub use profile::ProfileCredentialProvider;

mod sso;
pub use sso::SSOCredentialProvider;

mod r#static;
pub use r#static::StaticCredentialProvider;

mod utils;
