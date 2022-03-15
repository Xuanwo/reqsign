//! - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION
//! - The default credentials files located in ~/.aws/config and ~/.aws/credentials (location can vary per platform)
//! - Web Identity Token credentials from the environment or container (including EKS)
//! - ECS Container Credentials (IAM roles for tasks)
//! - EC2 Instance Metadata Service (IAM Roles attached to instance)

use std::str::FromStr;
use std::{env, fs};

use anyhow::Result;
use async_trait::async_trait;
use ini::Ini;
use log::debug;
use reqwest::Url;

use super::credential::Credential;
use crate::dirs::expand_homedir;
use crate::time;
use crate::time::ISO8601;

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
struct EnvLoader {}

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
struct ProfileLoader {}

#[async_trait]
impl CredentialLoad for ProfileLoader {
    async fn load_credential(&self) -> Result<Option<Credential>> {
        let cfg_path = env::var(super::constants::AWS_CONFIG_FILE)
            .unwrap_or_else(|_| "~/.aws/config".to_string());
        if let Some(cfg_path) = expand_homedir(&cfg_path) {
            if fs::metadata(&cfg_path).is_ok() {
                let conf = Ini::load_from_file(cfg_path)?;
                // NOTE: section in config must prefixed with "profile"
                if let Some(props) = conf.section(Some("profile default")) {
                    if let (Some(ak), Some(sk)) = (
                        props.get("aws_access_key_id"),
                        props.get("aws_secret_access_key"),
                    ) {
                        return Ok(Some(Credential::new(ak, sk)));
                    }
                }
            }
        }

        let cred_path = env::var(super::constants::AWS_SHARED_CREDENTIALS_FILE)
            .unwrap_or_else(|_| "~/.aws/credentials".to_string());
        if let Some(cred_path) = expand_homedir(&cred_path) {
            if fs::metadata(&cred_path).is_ok() {
                let conf = Ini::load_from_file(cred_path)?;
                // NOTE: section in config must not prefixed with "profile"
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

/// Load credential via web identity token
///
/// ## TODO
///
/// - Explain how web identity token works
/// - Support load web identity token from aws config.
/// - Support load session name from `AWS_ROLE_SESSION_NAME`
#[derive(Default, Clone, Debug)]
struct WebIdentityTokenLoader {
    // TODO: it seems we don't need region to start
// region: String,
}

#[async_trait]
impl CredentialLoad for WebIdentityTokenLoader {
    async fn load_credential(&self) -> Result<Option<Credential>> {
        if let (Ok(token), Ok(role_arn)) = (
            env::var(super::constants::AWS_WEB_IDENTITY_TOKEN_FILE),
            env::var(super::constants::AWS_ROLE_ARN),
        ) {
            let token = fs::read_to_string(token).expect("must valid");

            let mut url = Url::from_str("https://sts.amazonaws.com/").expect("must be valid url");
            url.query_pairs_mut()
                .append_pair("Action", "AssumeRoleWithWebIdentity")
                .append_pair("RoleArn", &role_arn)
                .append_pair("WebIdentityToken", &token);

            let mut req = reqwest::Request::new(http::Method::POST, url);
            req.headers_mut().insert(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded".parse()?,
            );
            let resp = reqwest::Client::new().execute(req).await?;
            debug!(
                "AWS STS services returns response with status code {}",
                resp.status()
            );
            if resp.status() == http::StatusCode::OK {
                let text = resp.text().await?;
                let doc = roxmltree::Document::parse(&text)?;
                let node = doc
                    .descendants()
                    .find(|n| n.tag_name().name() == "Credentials")
                    .unwrap();

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

                            builder.expires_in(time::parse(text, ISO8601)?);
                        }
                        _ => {}
                    }
                }
                let cred = builder.build()?;

                return Ok(Some(cred));
            }
        }

        Ok(None)
    }
}
