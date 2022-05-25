//! Loader is used to load credential or region from env.
//!
//! - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION
//! - The default credentials files located in ~/.aws/config and ~/.aws/credentials (location can vary per platform)
//! - Web Identity Token credentials from the environment or container (including EKS)
//! - ECS Container Credentials (IAM roles for tasks)
//! - EC2 Instance Metadata Service (IAM Roles attached to instance)

use std::str::FromStr;
use std::thread::sleep;
use std::{env, fs};

use anyhow::{anyhow, Result};
use ini::Ini;
use isahc::ReadResponseExt;
use log::warn;
use quick_xml::de;
use serde::Deserialize;

use super::credential::Credential;
use crate::dirs::expand_homedir;
use crate::time::parse_rfc3339;

/// Loader trait will try to load credential and region from different sources.
pub trait RegionLoad: Send + Sync {
    fn load_region(&self) -> Result<Option<String>>;
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

impl RegionLoad for RegionLoadChain {
    fn load_region(&self) -> Result<Option<String>> {
        for l in self.loaders.iter() {
            if let Some(r) = l.load_region()? {
                return Ok(Some(r));
            }
        }

        Ok(None)
    }
}

/// Loader trait will try to load credential and region from different sources.
pub trait CredentialLoad: Send + Sync {
    fn load_credential(&self) -> Result<Option<Credential>>;
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

impl CredentialLoad for CredentialLoadChain {
    fn load_credential(&self) -> Result<Option<Credential>> {
        for l in self.loaders.iter() {
            if let Some(c) = l.load_credential()? {
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

impl CredentialLoad for EnvLoader {
    fn load_credential(&self) -> Result<Option<Credential>> {
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

impl RegionLoad for EnvLoader {
    fn load_region(&self) -> Result<Option<String>> {
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
impl CredentialLoad for ProfileLoader {
    fn load_credential(&self) -> Result<Option<Credential>> {
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

impl RegionLoad for ProfileLoader {
    fn load_region(&self) -> Result<Option<String>> {
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

impl CredentialLoad for WebIdentityTokenLoader {
    fn load_credential(&self) -> Result<Option<Credential>> {
        if let (Ok(token), Ok(role_arn)) = (
            env::var(super::constants::AWS_WEB_IDENTITY_TOKEN_FILE),
            env::var(super::constants::AWS_ROLE_ARN),
        ) {
            let token = fs::read_to_string(token)
                .expect("must valid")
                .trim()
                .to_string();
            let role_session_name = env::var(super::constants::AWS_ROLE_SESSION_NAME)
                .unwrap_or_else(|_| "reqsign".to_string());

            let mut retry = backon::ExponentialBackoff::default();

            let mut resp = loop {
                // Construct request to AWS STS Service.
                let mut req = isahc::Request::new(isahc::Body::empty());
                let url = format!("https://sts.amazonaws.com/?Action=AssumeRoleWithWebIdentity&RoleArn={role_arn}&WebIdentityToken={token}&Version=2011-06-15&RoleSessionName={role_session_name}");
                *req.uri_mut() = http::Uri::from_str(&url).expect("must be valid url");
                req.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded".parse()?,
                );

                let mut resp = isahc::HttpClient::new()?.send(req)?;
                if resp.status() == http::StatusCode::OK {
                    break resp;
                } else {
                    let content = resp.text()?;
                    warn!("request to AWS STS Services failed: {content}");

                    match retry.next() {
                        Some(dur) => sleep(dur),
                        None => {
                            return Err(anyhow!(
                                "request to AWS STS Services still failed after retry: {}",
                                content
                            ))
                        }
                    }
                }
            };

            let resp: AssumeRoleWithWebIdentityResponse = de::from_str(&resp.text()?)?;
            let cred = resp.result.credentials;

            let mut builder = Credential::builder();
            builder.access_key(&cred.access_key_id);
            builder.secret_key(&cred.secret_access_key);
            builder.security_token(&cred.session_token);
            builder.expires_in(parse_rfc3339(&cred.expiration)?);

            return Ok(Some(builder.build()?));
        }

        Ok(None)
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: AssumeRoleWithWebIdentityResult,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResult {
    credentials: AssumeRoleWithWebIdentityCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    use quick_xml::de;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::services::aws::constants::*;

    static TOKIO: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("runtime must be valid"));

    #[test]
    fn test_credential_env_loader_without_env() {
        temp_env::with_vars_unset(vec![AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY], || {
            TOKIO.block_on(async {
                let l = EnvLoader {};
                let x = l.load_credential().expect("load_credential must success");
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
                        .expect("load_credential must success")
                        .expect("credential must be valid");
                    assert_eq!("shared_access_key_id", x.access_key());
                    assert_eq!("shared_secret_access_key", x.secret_key());
                });
            },
        );
    }

    #[test]
    fn test_region_env_loader_without_env() {
        temp_env::with_vars_unset(vec![AWS_REGION], || {
            TOKIO.block_on(async {
                let l = EnvLoader {};
                let x = l.load_region().expect("load_region must success");
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
                        .expect("load_credential must success")
                        .expect("region must be valid");
                    assert_eq!("test", x);
                });
            },
        );
    }

    #[test]
    fn test_parse_assume_role_with_web_identity_response() -> Result<()> {
        let content = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Audience>test_audience</Audience>
    <AssumedRoleUser>
      <AssumedRoleId>role_id:reqsign</AssumedRoleId>
      <Arn>arn:aws:sts::123:assumed-role/reqsign/reqsign</Arn>
    </AssumedRoleUser>
    <Provider>arn:aws:iam::123:oidc-provider/example.com/</Provider>
    <Credentials>
      <AccessKeyId>access_key_id</AccessKeyId>
      <SecretAccessKey>secret_access_key</SecretAccessKey>
      <SessionToken>session_token</SessionToken>
      <Expiration>2022-05-25T11:45:17Z</Expiration>
    </Credentials>
    <SubjectFromWebIdentityToken>subject</SubjectFromWebIdentityToken>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>b1663ad1-23ab-45e9-b465-9af30b202eba</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>"#;

        let resp: AssumeRoleWithWebIdentityResponse =
            de::from_str(content).expect("xml deserialize must success");

        assert_eq!(&resp.result.credentials.access_key_id, "access_key_id");
        assert_eq!(
            &resp.result.credentials.secret_access_key,
            "secret_access_key"
        );
        assert_eq!(&resp.result.credentials.session_token, "session_token");
        assert_eq!(&resp.result.credentials.expiration, "2022-05-25T11:45:17Z");

        Ok(())
    }
}
