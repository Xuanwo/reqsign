//! - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION
//! - The default credentials files located in ~/.aws/config and ~/.aws/credentials (location can vary per platform)
//! - Web Identity Token credentials from the environment or container (including EKS)
//! - ECS Container Credentials (IAM roles for tasks)
//! - EC2 Instance Metadata Service (IAM Roles attached to instance)

use std::str::FromStr;
use std::{env, fs};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ini::Ini;
use log::warn;
use reqwest::Url;

use super::credential::Credential;
use crate::dirs::expand_homedir;

use crate::time::parse_rfc3339;

/// Loader trait will try to load credential and region from different sources.
#[async_trait]
pub trait RegionLoad: Send + Sync {
    async fn load_region(&self) -> Result<Option<String>>;
}

#[derive(Default)]
pub struct RegionLoadChain {
    loaders: Vec<Box<dyn RegionLoad + 'static>>,
}

impl RegionLoadChain {
    pub fn is_empty(&self) -> bool {
        self.loaders.is_empty()
    }

    pub fn push(&mut self, l: impl RegionLoad + 'static) -> &mut Self {
        self.loaders.push(Box::new(l));

        self
    }
}

#[async_trait]
impl RegionLoad for RegionLoadChain {
    async fn load_region(&self) -> Result<Option<String>> {
        for l in self.loaders.iter() {
            if let Some(r) = l.load_region().await? {
                return Ok(Some(r));
            }
        }

        Ok(None)
    }
}

/// Loader trait will try to load credential and region from different sources.
#[async_trait]
pub trait CredentialLoad: Send + Sync {
    async fn load_credential(&self) -> Result<Option<Credential>>;
}

#[derive(Default)]
pub struct CredentialLoadChain {
    loaders: Vec<Box<dyn CredentialLoad>>,
}

impl CredentialLoadChain {
    pub fn is_empty(&self) -> bool {
        self.loaders.is_empty()
    }

    pub fn push(&mut self, l: impl CredentialLoad + 'static) -> &mut Self {
        self.loaders.push(Box::new(l));

        self
    }
}
#[async_trait]
impl CredentialLoad for CredentialLoadChain {
    async fn load_credential(&self) -> Result<Option<Credential>> {
        for l in self.loaders.iter() {
            if let Some(c) = l.load_credential().await? {
                return Ok(Some(c));
            }
        }

        Ok(None)
    }
}

/// Load credential from env values
///
/// - `AWS_ACCESS_KEY_ID`
/// - `AWS_SECRET_ACCESS_KEY`
/// - `AWS_REGION`
#[derive(Default, Clone, Debug)]
pub struct EnvLoader {}

#[async_trait]
impl CredentialLoad for EnvLoader {
    async fn load_credential(&self) -> Result<Option<Credential>> {
        if let (Ok(ak), Ok(sk)) = (
            env::var(super::constants::AWS_ACCESS_KEY_ID),
            env::var(super::constants::AWS_SECRET_ACCESS_KEY),
        ) {
            Ok(Some(Credential::new(&ak, &sk)))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl RegionLoad for EnvLoader {
    async fn load_region(&self) -> Result<Option<String>> {
        if let Ok(region) = env::var(super::constants::AWS_REGION) {
            Ok(Some(region))
        } else {
            Ok(None)
        }
    }
}

/// Load credential from AWS profiles
///
/// ## Location of Profile Files
///
/// - The location of the config file will be loaded from the `AWS_CONFIG_FILE` environment variable
/// with a fallback to `~/.aws/config`
/// - The location of the credentials file will be loaded from the `AWS_SHARED_CREDENTIALS_FILE`
/// environment variable with a fallback to `~/.aws/credentials`
///
/// `~` will be resolved by [`dirs-rs`](https://crates.io/crates/dirs).
///
/// ## TODO
///
/// - We only support `default` profile now, and `AWS_PROFILE` support should be added.
#[derive(Default, Clone, Debug)]
pub struct ProfileLoader {}

/// Comment from [Where are configuration settings stored?](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
///
/// > You can keep all of your profile settings in a single file as the AWS
/// > CLI can read credentials from the config file. If there are credentials
/// > in both files for a profile sharing the same name, the keys in the
/// > credentials file take precedence.
#[async_trait]
impl CredentialLoad for ProfileLoader {
    async fn load_credential(&self) -> Result<Option<Credential>> {
        let cred_path = env::var(super::constants::AWS_SHARED_CREDENTIALS_FILE)
            .unwrap_or_else(|_| "~/.aws/credentials".to_string());
        if let Some(cred_path) = expand_homedir(&cred_path) {
            if fs::metadata(&cred_path).is_ok() {
                let conf = Ini::load_from_file(cred_path)?;
                if let Some(props) = conf.section(Some("default")) {
                    if let (Some(ak), Some(sk)) = (
                        props.get("aws_access_key_id"),
                        props.get("aws_secret_access_key"),
                    ) {
                        return Ok(Some(Credential::new(ak, sk)));
                    }
                }
            }
        }

        let cfg_path = env::var(super::constants::AWS_CONFIG_FILE)
            .unwrap_or_else(|_| "~/.aws/config".to_string());
        if let Some(cfg_path) = expand_homedir(&cfg_path) {
            if fs::metadata(&cfg_path).is_ok() {
                let conf = Ini::load_from_file(cfg_path)?;
                if let Some(props) = conf.section(Some("default")) {
                    if let (Some(ak), Some(sk)) = (
                        props.get("aws_access_key_id"),
                        props.get("aws_secret_access_key"),
                    ) {
                        return Ok(Some(Credential::new(ak, sk)));
                    }
                }
            }
        }

        Ok(None)
    }
}

#[async_trait]
impl RegionLoad for ProfileLoader {
    async fn load_region(&self) -> Result<Option<String>> {
        let cfg_path = env::var(super::constants::AWS_CONFIG_FILE)
            .unwrap_or_else(|_| "~/.aws/config".to_string());
        if let Some(cfg_path) = expand_homedir(&cfg_path) {
            if fs::metadata(&cfg_path).is_ok() {
                let conf = Ini::load_from_file(cfg_path)?;
                if let Some(props) = conf.section(Some("default")) {
                    if let Some(region) = props.get("region") {
                        return Ok(Some(region.to_string()));
                    }
                }
            }
        }

        Ok(None)
    }
}

/// Load credential via web identity token
///
/// ## TODO
///
/// - Explain how web identity token works
/// - Support load web identity token file from aws config.
#[derive(Default, Clone, Debug)]
pub struct WebIdentityTokenLoader {}

#[async_trait]
impl CredentialLoad for WebIdentityTokenLoader {
    async fn load_credential(&self) -> Result<Option<Credential>> {
        if let (Ok(token), Ok(role_arn)) = (
            env::var(super::constants::AWS_WEB_IDENTITY_TOKEN_FILE),
            env::var(super::constants::AWS_ROLE_ARN),
        ) {
            let token = fs::read_to_string(token).expect("must valid");

            // Construct request to AWS STS Service.
            let mut url = Url::from_str("https://sts.amazonaws.com/").expect("must be valid url");
            url.query_pairs_mut()
                .append_pair("Action", "AssumeRoleWithWebIdentity")
                .append_pair("RoleArn", &role_arn)
                .append_pair("WebIdentityToken", &token)
                .append_pair("Version", "2011-06-15")
                .append_pair(
                    "RoleSessionName",
                    &env::var(super::constants::AWS_ROLE_SESSION_NAME)
                        .unwrap_or_else(|_| "reqsign".to_string()),
                );
            let mut req = reqwest::Request::new(http::Method::POST, url);
            req.headers_mut().insert(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded".parse()?,
            );

            // Sending and parse response from STS service
            let resp = reqwest::Client::new().execute(req).await?;
            if resp.status() == http::StatusCode::OK {
                let text = resp.text().await?;
                let doc = roxmltree::Document::parse(&text)?;
                let node = doc
                    .descendants()
                    .find(|n| n.tag_name().name() == "Credentials")
                    .ok_or_else(|| anyhow!("Credentials not found in STS response"))?;

                let mut builder = Credential::builder();
                for n in node.children() {
                    match n.tag_name().name() {
                        "AccessKeyId" => {
                            builder.access_key(n.text().expect("AccessKeyId must be exist"));
                        }
                        "SecretAccessKey" => {
                            builder.secret_key(n.text().expect("SecretAccessKey must be exist"));
                        }
                        "SessionToken" => {
                            builder.security_token(n.text().expect("SessionToken must be exist"));
                        }
                        "Expiration" => {
                            let text = n.text().expect("Expiration must be exist");

                            builder.expires_in(parse_rfc3339(text)?);
                        }
                        _ => {}
                    }
                }
                let cred = builder.build()?;

                return Ok(Some(cred));
            } else {
                // Print error response if we request sts service failed.
                warn!("request to AWS STS Services failed: {}", resp.text().await?)
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use log::debug;
    use once_cell::sync::Lazy;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::services::aws::constants::*;

    static TOKIO: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("runtime must be valid"));

    #[test]
    fn test_credential_env_loader_without_env() {
        temp_env::with_vars_unset(vec![AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY], || {
            TOKIO.block_on(async {
                let l = EnvLoader {};
                let x = l
                    .load_credential()
                    .await
                    .expect("load_credential must success");
                assert!(x.is_none());
            });
        });
    }

    #[test]
    fn test_credential_env_loader_with_env() {
        temp_env::with_vars(
            vec![
                (AWS_ACCESS_KEY_ID, Some("access_key_id")),
                (AWS_SECRET_ACCESS_KEY, Some("secret_access_key")),
            ],
            || {
                TOKIO.block_on(async {
                    let l = EnvLoader {};
                    let x = l
                        .load_credential()
                        .await
                        .expect("load_credential must success")
                        .expect("credential must be valid");
                    assert_eq!("access_key_id", x.access_key());
                    assert_eq!("secret_access_key", x.secret_key());
                });
            },
        );
    }

    #[test]
    fn test_credential_profile_loader_from_config() {
        temp_env::with_vars(
            vec![
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_config",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/not_exist",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                TOKIO.block_on(async {
                    let l = ProfileLoader {};
                    let x = l
                        .load_credential()
                        .await
                        .expect("load_credential must success")
                        .expect("credential must be valid");
                    assert_eq!("config_access_key_id", x.access_key());
                    assert_eq!("config_secret_access_key", x.secret_key());
                });
            },
        );
    }

    #[test]
    fn test_credential_profile_loader_from_shared() {
        temp_env::with_vars(
            vec![
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/not_exist",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_credential",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                TOKIO.block_on(async {
                    let l = ProfileLoader {};
                    let x = l
                        .load_credential()
                        .await
                        .expect("load_credential must success")
                        .expect("credential must be valid");
                    assert_eq!("shared_access_key_id", x.access_key());
                    assert_eq!("shared_secret_access_key", x.secret_key());
                });
            },
        );
    }

    /// AWS_SHARED_CREDENTIALS_FILE should be taken first.
    #[test]
    fn test_credential_profile_loader_from_both() {
        temp_env::with_vars(
            vec![
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_config",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_credential",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                TOKIO.block_on(async {
                    let l = ProfileLoader {};
                    let x = l
                        .load_credential()
                        .await
                        .expect("load_credential must success")
                        .expect("credential must be valid");
                    assert_eq!("shared_access_key_id", x.access_key());
                    assert_eq!("shared_secret_access_key", x.secret_key());
                });
            },
        );
    }

    /// This test relay on `AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN`
    /// been set correctly.
    ///
    /// Please verify logic manually until we find a way to test it.
    #[test]
    #[ignore]
    fn test_credential_web_loader() {
        env_logger::init();

        TOKIO.block_on(async {
            let l = WebIdentityTokenLoader {};
            let x = l
                .load_credential()
                .await
                .expect("load_credential must success")
                .expect("credential must be valid");
            debug!(
                "ak: {}, sk: {}, token: {:?}, valid: {}",
                x.access_key(),
                x.secret_key(),
                x.security_token(),
                x.is_valid()
            );
        });
    }

    #[test]
    fn test_region_env_loader_without_env() {
        temp_env::with_vars_unset(vec![AWS_REGION], || {
            TOKIO.block_on(async {
                let l = EnvLoader {};
                let x = l.load_region().await.expect("load_region must success");
                assert!(x.is_none());
            });
        });
    }

    #[test]
    fn test_region_env_loader_with_env() {
        temp_env::with_vars(vec![(AWS_REGION, Some("test"))], || {
            TOKIO.block_on(async {
                let l = EnvLoader {};
                let x = l
                    .load_region()
                    .await
                    .expect("load_credential must success")
                    .expect("region must be valid");
                assert_eq!("test", x);
            });
        });
    }

    #[test]
    fn test_region_profile_loader() {
        temp_env::with_vars(
            vec![(
                AWS_CONFIG_FILE,
                Some(format!(
                    "{}/testdata/services/aws/default_config",
                    env::current_dir()
                        .expect("current_dir must exist")
                        .to_string_lossy()
                )),
            )],
            || {
                TOKIO.block_on(async {
                    let l = ProfileLoader {};
                    let x = l
                        .load_region()
                        .await
                        .expect("load_credential must success")
                        .expect("region must be valid");
                    assert_eq!("test", x);
                });
            },
        );
    }
}
