mod assume_role;
pub use assume_role::AssumeRoleLoader;

mod assume_role_with_web_identity;
pub use assume_role_with_web_identity::AssumeRoleWithWebIdentityLoader;

mod config;
pub use config::ConfigLoader;

mod default;
pub use default::DefaultLoader;

mod imds;
pub use imds::IMDSv2Loader;

mod utils;
