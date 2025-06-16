mod config;
pub use config::ConfigLoader;

mod default;
pub use default::DefaultLoader;

mod assume_role_with_web_identity;
pub use assume_role_with_web_identity::AssumeRoleWithWebIdentityLoader;
