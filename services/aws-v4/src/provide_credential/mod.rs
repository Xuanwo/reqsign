mod assume_role;
pub use assume_role::AssumeRoleCredentialProvider;

mod assume_role_with_web_identity;
pub use assume_role_with_web_identity::AssumeRoleWithWebIdentityCredentialProvider;

mod default;
pub use default::DefaultCredentialProvider;

mod env;
pub use env::EnvCredentialProvider;

mod imds;
pub use imds::IMDSv2CredentialProvider;

mod profile;
pub use profile::ProfileCredentialProvider;

mod r#static;
pub use r#static::StaticCredentialProvider;

mod utils;
