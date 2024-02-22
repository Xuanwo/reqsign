use std::fmt::Debug;
use std::fmt::Write;
use std::fs;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::anyhow;
use anyhow::Result;
use async_trait::async_trait;
use http::header::CONTENT_LENGTH;
use log::debug;
use quick_xml::de;
use reqwest::Client;
use serde::Deserialize;

use super::config::Config;
use super::constants::X_AMZ_CONTENT_SHA_256;
use super::v4::Signer;
use crate::time::now;
use crate::time::parse_rfc3339;
use crate::time::DateTime;

pub const EMPTY_STRING_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Credential that holds the access_key and secret_key.
#[derive(Default, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Credential {
    /// Access key id for aws services.
    pub access_key_id: String,
    /// Secret access key for aws services.
    pub secret_access_key: String,
    /// Session token for aws services.
    pub session_token: Option<String>,
    /// Expiration time for this credential.
    pub expires_in: Option<DateTime>,
}

impl Credential {
    /// is current cred is valid?
    pub fn is_valid(&self) -> bool {
        if (self.access_key_id.is_empty() || self.secret_access_key.is_empty())
            && self.session_token.is_none()
        {
            return false;
        }
        // Take 120s as buffer to avoid edge cases.
        if let Some(valid) = self
            .expires_in
            .map(|v| v > now() + chrono::Duration::minutes(2))
        {
            return valid;
        }

        true
    }
}

/// Loader trait will try to load credential from different sources.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait CredentialLoad: 'static + Send + Sync {
    /// Load credential from sources.
    ///
    /// - If succeed, return `Ok(Some(cred))`
    /// - If not found, return `Ok(None)`
    /// - If unexpected errors happened, return `Err(err)`
    async fn load_credential(&self, client: Client) -> Result<Option<Credential>>;
}

/// CredentialLoader will load credential from different methods.
pub struct DefaultLoader {
    client: Client,
    config: Config,
    credential: Arc<Mutex<Option<Credential>>>,
    imds_v2_loader: Option<IMDSv2Loader>,
}

impl DefaultLoader {
    /// Create a new CredentialLoader
    pub fn new(client: Client, config: Config) -> Self {
        let imds_v2_loader = if config.ec2_metadata_disabled {
            None
        } else {
            Some(IMDSv2Loader::new(client.clone()))
        };
        Self {
            client,
            config,
            credential: Arc::default(),
            imds_v2_loader,
        }
    }

    /// Disable load from ec2 metadata.
    pub fn with_disable_ec2_metadata(mut self) -> Self {
        self.imds_v2_loader = None;
        self
    }

    /// Load credential.
    ///
    /// Resolution order:
    /// 1. Environment variables
    /// 2. Shared config (`~/.aws/config`, `~/.aws/credentials`)
    /// 3. Web Identity Tokens
    /// 4. ECS (IAM Roles for Tasks) & General HTTP credentials:
    /// 5. EC2 IMDSv2
    pub async fn load(&self) -> Result<Option<Credential>> {
        // Return cached credential if it has been loaded at least once.
        match self.credential.lock().expect("lock poisoned").clone() {
            Some(cred) if cred.is_valid() => return Ok(Some(cred)),
            _ => (),
        }

        let cred = self.load_inner().await?;

        let mut lock = self.credential.lock().expect("lock poisoned");
        *lock = cred.clone();

        Ok(cred)
    }

    async fn load_inner(&self) -> Result<Option<Credential>> {
        if let Some(cred) = self.load_via_config().map_err(|err| {
            debug!("load credential via config failed: {err:?}");
            err
        })? {
            return Ok(Some(cred));
        }

        if let Some(cred) = self
            .load_via_assume_role_with_web_identity()
            .await
            .map_err(|err| {
                debug!("load credential via assume_role_with_web_identity failed: {err:?}");
                err
            })?
        {
            return Ok(Some(cred));
        }

        if let Some(cred) = self.load_via_imds_v2().await.map_err(|err| {
            debug!("load credential via imds_v2 failed: {err:?}");
            err
        })? {
            return Ok(Some(cred));
        }

        Ok(None)
    }

    fn load_via_config(&self) -> Result<Option<Credential>> {
        if let (Some(ak), Some(sk)) = (&self.config.access_key_id, &self.config.secret_access_key) {
            Ok(Some(Credential {
                access_key_id: ak.clone(),
                secret_access_key: sk.clone(),
                session_token: self.config.session_token.clone(),
                // Set expires_in to 10 minutes to enforce re-read
                // from file.
                expires_in: Some(now() + chrono::Duration::minutes(10)),
            }))
        } else {
            Ok(None)
        }
    }

    async fn load_via_imds_v2(&self) -> Result<Option<Credential>> {
        let loader = match &self.imds_v2_loader {
            Some(loader) => loader,
            None => return Ok(None),
        };

        loader.load().await
    }

    async fn load_via_assume_role_with_web_identity(&self) -> Result<Option<Credential>> {
        let (token_file, role_arn) =
            match (&self.config.web_identity_token_file, &self.config.role_arn) {
                (Some(token_file), Some(role_arn)) => (token_file, role_arn),
                _ => return Ok(None),
            };

        let token = fs::read_to_string(token_file)?;
        let role_session_name = &self.config.role_session_name;

        let endpoint = self.sts_endpoint()?;

        // Construct request to AWS STS Service.
        let url = format!("https://{endpoint}/?Action=AssumeRoleWithWebIdentity&RoleArn={role_arn}&WebIdentityToken={token}&Version=2011-06-15&RoleSessionName={role_session_name}");
        let req = self.client.get(&url).header(
            http::header::CONTENT_TYPE.as_str(),
            "application/x-www-form-urlencoded",
        );

        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!("request to AWS STS Services failed: {content}"));
        }

        let resp: AssumeRoleWithWebIdentityResponse = de::from_str(&resp.text().await?)?;
        let resp_cred = resp.result.credentials;

        let cred = Credential {
            access_key_id: resp_cred.access_key_id,
            secret_access_key: resp_cred.secret_access_key,
            session_token: Some(resp_cred.session_token),
            expires_in: Some(parse_rfc3339(&resp_cred.expiration)?),
        };

        Ok(Some(cred))
    }

    /// Get the sts endpoint.
    ///
    /// The returning format may look like `sts.{region}.amazonaws.com`
    ///
    /// # Notes
    ///
    /// AWS could have different sts endpoint based on it's region.
    /// We can check them by region name.
    ///
    /// ref: https://github.com/awslabs/aws-sdk-rust/blob/31cfae2cf23be0c68a47357070dea1aee9227e3a/sdk/sts/src/aws_endpoint.rs
    fn sts_endpoint(&self) -> Result<String> {
        // use regional sts if sts_regional_endpoints has been set.
        if self.config.sts_regional_endpoints == "regional" {
            let region = self.config.region.clone().ok_or_else(|| {
                anyhow!("sts_regional_endpoints set to reginal, but region is not set")
            })?;
            if region.starts_with("cn-") {
                Ok(format!("sts.{region}.amazonaws.com.cn"))
            } else {
                Ok(format!("sts.{region}.amazonaws.com"))
            }
        } else {
            let region = self.config.region.clone().unwrap_or_default();
            if region.starts_with("cn") {
                // TODO: seems aws china doesn't support global sts?
                Ok("sts.amazonaws.com.cn".to_string())
            } else {
                Ok("sts.amazonaws.com".to_string())
            }
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl CredentialLoad for DefaultLoader {
    async fn load_credential(&self, _: Client) -> Result<Option<Credential>> {
        self.load().await
    }
}

pub struct IMDSv2Loader {
    client: Client,

    token: Arc<Mutex<(String, DateTime)>>,
}

impl IMDSv2Loader {
    /// Create a new IMDSv2Loader.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            token: Arc::new(Mutex::new(("".to_string(), DateTime::MIN_UTC))),
        }
    }

    pub async fn load(&self) -> Result<Option<Credential>> {
        let token = self.load_ec2_metadata_token().await?;

        // List all credentials that node has.
        let url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        let req = self
            .client
            .get(url)
            .header("x-aws-ec2-metadata-token", &token);
        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }
        let profile_name = resp.text().await?;

        // Get the credentials via role_name.
        let url = format!(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/{profile_name}"
        );
        let req = self
            .client
            .get(&url)
            .header("x-aws-ec2-metadata-token", &token);
        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }

        let content = resp.text().await?;
        let resp: Ec2MetadataIamSecurityCredentials = serde_json::from_str(&content)?;
        if resp.code != "Success" {
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }

        let cred = Credential {
            access_key_id: resp.access_key_id,
            secret_access_key: resp.secret_access_key,
            session_token: Some(resp.token),
            expires_in: Some(parse_rfc3339(&resp.expiration)?),
        };

        Ok(Some(cred))
    }

    /// load_ec2_metadata_token will load ec2 metadata token from IMDS.
    ///
    /// Return value is (token, expires_in).
    async fn load_ec2_metadata_token(&self) -> Result<String> {
        {
            let (token, expires_in) = self.token.lock().expect("lock poisoned").clone();
            if expires_in > now() {
                return Ok(token);
            }
        }

        let url = "http://169.254.169.254/latest/api/token";
        #[allow(unused_mut)]
        let mut req = self
            .client
            .put(url)
            .header(CONTENT_LENGTH, "0")
            // 21600s (6h) is recommended by AWS.
            .header("x-aws-ec2-metadata-token-ttl-seconds", "21600");

        // Set timeout to 1s to avoid hanging on non-s3 env.
        #[cfg(not(target_arch = "wasm32"))]
        {
            req = req.timeout(std::time::Duration::from_secs(1));
        }

        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }
        let ec2_token = resp.text().await?;
        // Set expires_in to 10 minutes to enforce re-read.
        let expires_in = now() + chrono::Duration::seconds(21600) - chrono::Duration::seconds(600);

        {
            *self.token.lock().expect("lock poisoned") = (ec2_token.clone(), expires_in);
        }

        Ok(ec2_token)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl CredentialLoad for IMDSv2Loader {
    async fn load_credential(&self, _: Client) -> Result<Option<Credential>> {
        self.load().await
    }
}

/// AssumeRoleLoader will load credential via assume role.
pub struct AssumeRoleLoader {
    client: Client,
    config: Config,

    source_credential: Box<dyn CredentialLoad>,
    sts_signer: Signer,
}

impl AssumeRoleLoader {
    /// Create a new assume role loader.
    pub fn new(
        client: Client,
        config: Config,
        source_credential: Box<dyn CredentialLoad>,
    ) -> Result<Self> {
        let region = config.region.clone().ok_or_else(|| {
            anyhow!("assume role loader requires region, but not found, please check your configuration")
        })?;

        Ok(Self {
            client,
            config,
            source_credential,

            sts_signer: Signer::new("sts", &region),
        })
    }

    /// Load credential via assume role.
    pub async fn load(&self) -> Result<Option<Credential>> {
        let role_arn =self.config.role_arn.clone().ok_or_else(|| {
            anyhow!("assume role loader requires role_arn, but not found, please check your configuration")
        })?;

        let role_session_name = &self.config.role_session_name;

        let endpoint = self.sts_endpoint()?;

        // Construct request to AWS STS Service.
        let mut url = format!("https://{endpoint}/?Action=AssumeRole&RoleArn={role_arn}&Version=2011-06-15&RoleSessionName={role_session_name}");
        if let Some(external_id) = &self.config.external_id {
            write!(url, "&ExternalId={external_id}")?;
        }
        let mut req = self
            .client
            .get(&url)
            .header(
                http::header::CONTENT_TYPE.as_str(),
                "application/x-www-form-urlencoded",
            )
            // Set content sha to empty string.
            .header(X_AMZ_CONTENT_SHA_256, EMPTY_STRING_SHA256)
            .build()?;

        let source_cred = self
            .source_credential
            .load_credential(self.client.clone())
            .await?
            .ok_or_else(|| {
                anyhow!("source credential is required for AssumeRole, but not found, please check your configuration")
            })?;

        self.sts_signer.sign(&mut req, &source_cred)?;

        let resp = self.client.execute(req).await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!("request to AWS STS Services failed: {content}"));
        }

        let resp: AssumeRoleResponse = de::from_str(&resp.text().await?)?;
        let resp_cred = resp.result.credentials;

        let cred = Credential {
            access_key_id: resp_cred.access_key_id,
            secret_access_key: resp_cred.secret_access_key,
            session_token: Some(resp_cred.session_token),
            expires_in: Some(parse_rfc3339(&resp_cred.expiration)?),
        };

        Ok(Some(cred))
    }

    /// Get the sts endpoint.
    ///
    /// The returning format may look like `sts.{region}.amazonaws.com`
    ///
    /// # Notes
    ///
    /// AWS could have different sts endpoint based on it's region.
    /// We can check them by region name.
    ///
    /// ref: https://github.com/awslabs/aws-sdk-rust/blob/31cfae2cf23be0c68a47357070dea1aee9227e3a/sdk/sts/src/aws_endpoint.rs
    fn sts_endpoint(&self) -> Result<String> {
        // use regional sts if sts_regional_endpoints has been set.
        if self.config.sts_regional_endpoints == "regional" {
            let region = self.config.region.clone().ok_or_else(|| {
                anyhow!("sts_regional_endpoints set to reginal, but region is not set")
            })?;
            if region.starts_with("cn-") {
                Ok(format!("sts.{region}.amazonaws.com.cn"))
            } else {
                Ok(format!("sts.{region}.amazonaws.com"))
            }
        } else {
            let region = self.config.region.clone().unwrap_or_default();
            if region.starts_with("cn") {
                // TODO: seems aws china doesn't support global sts?
                Ok("sts.amazonaws.com.cn".to_string())
            } else {
                Ok("sts.amazonaws.com".to_string())
            }
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl CredentialLoad for AssumeRoleLoader {
    async fn load_credential(&self, _: Client) -> Result<Option<Credential>> {
        self.load().await
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

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleResponse {
    #[serde(rename = "AssumeRoleResult")]
    result: AssumeRoleResult,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleResult {
    credentials: AssumeRoleCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct Ec2MetadataIamSecurityCredentials {
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: String,

    code: String,
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::str::FromStr;
    use std::vec;

    use anyhow::Result;
    use http::Request;
    use http::StatusCode;
    use once_cell::sync::Lazy;
    use quick_xml::de;
    use reqwest::Client;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::aws::constants::*;
    use crate::aws::v4::Signer;

    static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Should create a tokio runtime")
    });

    #[test]
    fn test_credential_env_loader_without_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars_unset(vec![AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY], || {
            RUNTIME.block_on(async {
                let l = DefaultLoader::new(reqwest::Client::new(), Config::default())
                    .with_disable_ec2_metadata();
                let x = l.load().await.expect("load must succeed");
                assert!(x.is_none());
            })
        });
    }

    #[test]
    fn test_credential_env_loader_with_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (AWS_ACCESS_KEY_ID, Some("access_key_id")),
                (AWS_SECRET_ACCESS_KEY, Some("secret_access_key")),
            ],
            || {
                RUNTIME.block_on(async {
                    let l = DefaultLoader::new(Client::new(), Config::default().from_env());
                    let x = l.load().await.expect("load must succeed");

                    let x = x.expect("must load succeed");
                    assert_eq!("access_key_id", x.access_key_id);
                    assert_eq!("secret_access_key", x.secret_access_key);
                })
            },
        );
    }

    #[test]
    fn test_credential_profile_loader_from_config() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (AWS_ACCESS_KEY_ID, None),
                (AWS_SECRET_ACCESS_KEY, None),
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
                RUNTIME.block_on(async {
                    let l = DefaultLoader::new(
                        Client::new(),
                        Config::default().from_env().from_profile(),
                    );
                    let x = l.load().await.unwrap().unwrap();
                    assert_eq!("config_access_key_id", x.access_key_id);
                    assert_eq!("config_secret_access_key", x.secret_access_key);
                })
            },
        );
    }

    #[test]
    fn test_credential_profile_loader_from_shared() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (AWS_ACCESS_KEY_ID, None),
                (AWS_SECRET_ACCESS_KEY, None),
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/not_exist",
                        env::current_dir()
                            .expect("load must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_credential",
                        env::current_dir()
                            .expect("load must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                RUNTIME.block_on(async {
                    let l = DefaultLoader::new(
                        Client::new(),
                        Config::default().from_env().from_profile(),
                    );
                    let x = l.load().await.unwrap().unwrap();
                    assert_eq!("shared_access_key_id", x.access_key_id);
                    assert_eq!("shared_secret_access_key", x.secret_access_key);
                })
            },
        );
    }

    /// AWS_SHARED_CREDENTIALS_FILE should be taken first.
    #[test]
    fn test_credential_profile_loader_from_both() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (AWS_ACCESS_KEY_ID, None),
                (AWS_SECRET_ACCESS_KEY, None),
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
                RUNTIME.block_on(async {
                    let l = DefaultLoader::new(
                        Client::new(),
                        Config::default().from_env().from_profile(),
                    );
                    let x = l.load().await.expect("load must success").unwrap();
                    assert_eq!("shared_access_key_id", x.access_key_id);
                    assert_eq!("shared_secret_access_key", x.secret_access_key);
                })
            },
        );
    }

    #[test]
    fn test_signer_with_web_loader() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        dotenv::from_filename(".env").ok();

        if env::var("REQSIGN_AWS_S3_TEST").is_err()
            || env::var("REQSIGN_AWS_S3_TEST").unwrap() != "on"
        {
            return Ok(());
        }

        // Ignore test if role_arn not set
        let role_arn = if let Ok(v) = env::var("REQSIGN_AWS_ASSUME_ROLE_ARN") {
            v
        } else {
            return Ok(());
        };

        // let provider_arn = env::var("REQSIGN_AWS_PROVIDER_ARN").expect("REQSIGN_AWS_PROVIDER_ARN not exist");
        let region = env::var("REQSIGN_AWS_S3_REGION").expect("REQSIGN_AWS_S3_REGION not exist");

        let github_token = env::var("GITHUB_ID_TOKEN").expect("GITHUB_ID_TOKEN not exist");
        let file_path = format!(
            "{}/testdata/services/aws/web_identity_token_file",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );
        fs::write(&file_path, github_token)?;

        temp_env::with_vars(
            vec![
                (AWS_REGION, Some(&region)),
                (AWS_ROLE_ARN, Some(&role_arn)),
                (AWS_WEB_IDENTITY_TOKEN_FILE, Some(&file_path)),
            ],
            || {
                RUNTIME.block_on(async {
                    let config = Config::default().from_env();
                    let loader = DefaultLoader::new(reqwest::Client::new(), config);

                    let signer = Signer::new("s3", &region);

                    let endpoint = format!("https://s3.{}.amazonaws.com/opendal-testing", region);
                    let mut req = Request::new("");
                    *req.method_mut() = http::Method::GET;
                    *req.uri_mut() =
                        http::Uri::from_str(&format!("{}/{}", endpoint, "not_exist_file")).unwrap();

                    let cred = loader
                        .load()
                        .await
                        .expect("credential must be valid")
                        .unwrap();

                    signer.sign(&mut req, &cred).expect("sign must success");

                    debug!("signed request url: {:?}", req.uri().to_string());
                    debug!("signed request: {:?}", req);

                    let client = Client::new();
                    let resp = client.execute(req.try_into().unwrap()).await.unwrap();

                    let status = resp.status();
                    debug!("got response: {:?}", resp);
                    debug!("got response content: {:?}", resp.text().await.unwrap());
                    assert_eq!(status, StatusCode::NOT_FOUND);
                })
            },
        );

        Ok(())
    }

    #[test]
    fn test_signer_with_web_loader_assume_role() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        dotenv::from_filename(".env").ok();

        if env::var("REQSIGN_AWS_S3_TEST").is_err()
            || env::var("REQSIGN_AWS_S3_TEST").unwrap() != "on"
        {
            return Ok(());
        }

        // Ignore test if role_arn not set
        let role_arn = if let Ok(v) = env::var("REQSIGN_AWS_ROLE_ARN") {
            v
        } else {
            return Ok(());
        };
        // Ignore test if assume_role_arn not set
        let assume_role_arn = if let Ok(v) = env::var("REQSIGN_AWS_ASSUME_ROLE_ARN") {
            v
        } else {
            return Ok(());
        };

        let region = env::var("REQSIGN_AWS_S3_REGION").expect("REQSIGN_AWS_S3_REGION not exist");

        let github_token = env::var("GITHUB_ID_TOKEN").expect("GITHUB_ID_TOKEN not exist");
        let file_path = format!(
            "{}/testdata/services/aws/web_identity_token_file",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );
        fs::write(&file_path, github_token)?;

        temp_env::with_vars(
            vec![
                (AWS_REGION, Some(&region)),
                (AWS_ROLE_ARN, Some(&role_arn)),
                (AWS_WEB_IDENTITY_TOKEN_FILE, Some(&file_path)),
            ],
            || {
                RUNTIME.block_on(async {
                    let client = reqwest::Client::new();
                    let default_loader =
                        DefaultLoader::new(client.clone(), Config::default().from_env())
                            .with_disable_ec2_metadata();

                    let cfg = Config {
                        role_arn: Some(assume_role_arn.clone()),
                        region: Some(region.clone()),
                        sts_regional_endpoints: "regional".to_string(),
                        ..Default::default()
                    };
                    let loader =
                        AssumeRoleLoader::new(client.clone(), cfg, Box::new(default_loader))
                            .expect("AssumeRoleLoader must be valid");

                    let signer = Signer::new("s3", &region);
                    let endpoint = format!("https://s3.{}.amazonaws.com/opendal-testing", region);
                    let mut req = Request::new("");
                    *req.method_mut() = http::Method::GET;
                    *req.uri_mut() =
                        http::Uri::from_str(&format!("{}/{}", endpoint, "not_exist_file")).unwrap();
                    let cred = loader
                        .load()
                        .await
                        .expect("credential must be valid")
                        .unwrap();
                    signer.sign(&mut req, &cred).expect("sign must success");
                    debug!("signed request url: {:?}", req.uri().to_string());
                    debug!("signed request: {:?}", req);
                    let client = Client::new();
                    let resp = client.execute(req.try_into().unwrap()).await.unwrap();
                    let status = resp.status();
                    debug!("got response: {:?}", resp);
                    debug!("got response content: {:?}", resp.text().await.unwrap());
                    assert_eq!(status, StatusCode::NOT_FOUND);
                })
            },
        );
        Ok(())
    }

    #[test]
    fn test_parse_assume_role_with_web_identity_response() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

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

    #[test]
    fn test_parse_assume_role_response() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let content = r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
  <SourceIdentity>Alice</SourceIdentity>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/TestAR</Arn>
      <AssumedRoleId>ARO123EXAMPLE123:TestAR</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <SessionToken>
       AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW
       LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd
       QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU
       9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz
       +scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==
      </SessionToken>
      <Expiration>2019-11-09T13:34:41Z</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>"#;

        let resp: AssumeRoleResponse = de::from_str(content).expect("xml deserialize must success");

        assert_eq!(
            &resp.result.credentials.access_key_id,
            "ASIAIOSFODNN7EXAMPLE"
        );
        assert_eq!(
            &resp.result.credentials.secret_access_key,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
        );
        assert_eq!(
            &resp.result.credentials.session_token,
            "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW
       LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd
       QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU
       9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz
       +scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=="
        );
        assert_eq!(&resp.result.credentials.expiration, "2019-11-09T13:34:41Z");

        Ok(())
    }
}
