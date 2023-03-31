use std::fmt::Write;
use std::fs;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::anyhow;
use anyhow::Result;
use log::warn;
use quick_xml::de;
use reqwest::Client;
use serde::Deserialize;

use super::config::Config;
use crate::credential::Credential;
use crate::credential::CredentialLoad;
use crate::time::parse_rfc3339;

/// CredentialLoader will load credential from different methods.
#[cfg_attr(test, derive(Debug))]
pub struct Loader {
    client: Client,
    config: Config,

    allow_anonymous: bool,
    disable_ec2_metadata: bool,
    customed_credential_loader: Option<Arc<dyn CredentialLoad>>,

    loaded: AtomicBool,
    credential: Arc<Mutex<Option<Credential>>>,
}

impl Loader {
    /// Create a new CredentialLoader
    pub fn new(client: Client, config: Config) -> Self {
        Self {
            client,
            config,

            allow_anonymous: false,
            disable_ec2_metadata: false,
            customed_credential_loader: None,

            loaded: AtomicBool::new(false),
            credential: Arc::default(),
        }
    }

    /// Allow anonymous.
    ///
    /// By enabling this option, CredentialLoader will not retry after
    /// loading credential failed.
    pub fn with_allow_anonymous(mut self) -> Self {
        self.allow_anonymous = true;
        self
    }

    /// Disable load from ec2 metadata.
    pub fn with_disable_ec2_metadata(mut self) -> Self {
        self.disable_ec2_metadata = true;
        self
    }

    /// Set customed credential loader.
    ///
    /// This loader will be used first.
    pub fn with_customed_credential_loader(mut self, f: Arc<dyn CredentialLoad>) -> Self {
        self.customed_credential_loader = Some(f);
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
        if self.loaded.load(Ordering::Relaxed) {
            match self.credential.lock().expect("lock poisoned").clone() {
                Some(cred) if cred.is_valid() => return Ok(Some(cred)),
                None if self.allow_anonymous => return Ok(None),
                _ => (),
            }
        }

        let cred = self.load_inner().await?;

        let mut lock = self.credential.lock().expect("lock poisoned");
        *lock = cred.clone();
        // Set loaded after we have updated the credential.
        self.loaded.store(true, Ordering::Relaxed);

        Ok(cred)
    }

    async fn load_inner(&self) -> Result<Option<Credential>> {
        if let Some(cred) = self.load_via_customed_credential_load().map_err(|err| {
            warn!("load credential via customed credential load failed: {err:?}");
            err
        })? {
            return Ok(Some(cred));
        }

        if let Some(cred) = self.load_via_config()? {
            return Ok(Some(cred));
        }

        if let Some(cred) = self
            .load_via_assume_role_with_web_identity()
            .await
            .map_err(|err| {
                warn!("load credential via assume role with web identity failed: {err:?}");
                err
            })?
        {
            return Ok(Some(cred));
        }

        if let Some(cred) = self.load_via_assume_role().await.map_err(|err| {
            warn!("load credential via assume role failed: {err:?}");
            err
        })? {
            return Ok(Some(cred));
        }

        if let Some(cred) = self.load_via_imds_v2().await.map_err(|err| {
            warn!("load credential via imds v2 failed: {err:?}");
            err
        })? {
            return Ok(Some(cred));
        }

        Ok(None)
    }

    fn load_via_customed_credential_load(&self) -> Result<Option<Credential>> {
        if let Some(loader) = &self.customed_credential_loader {
            loader.load_credential()
        } else {
            Ok(None)
        }
    }

    fn load_via_config(&self) -> Result<Option<Credential>> {
        if let (Some(ak), Some(sk)) = (&self.config.access_key_id, &self.config.secret_access_key) {
            let mut cred = Credential::new(ak, sk);
            if let Some(tk) = &self.config.session_token {
                cred.set_security_token(tk);
            }
            Ok(Some(cred))
        } else {
            Ok(None)
        }
    }

    async fn load_via_imds_v2(&self) -> Result<Option<Credential>> {
        if self.disable_ec2_metadata {
            return Ok(None);
        }

        // Get ec2 metadata token
        let url = "http://169.254.169.254/latest/api/token";
        let req = self
            .client
            .put(url)
            .header("x-aws-ec2-metadata-token-ttl-seconds", "60");
        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }
        let ec2_token = resp.text().await?;

        // List all credentials that node has.
        let url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        let req = self
            .client
            .get(url)
            .header("x-aws-ec2-metadata-token", &ec2_token);
        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {content}"
            ));
        }
        let content = resp.text().await?;
        let credential_list: Vec<_> = content.split('\n').collect();
        // credential list is empty, return None directly.
        if credential_list.is_empty() {
            return Ok(None);
        }
        let role_name = credential_list[0];

        // Get the credentials via role_name.
        let url =
            format!("http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}");
        let req = self
            .client
            .get(&url)
            .header("x-aws-ec2-metadata-token", &ec2_token);
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

        let cred = Credential::new(&resp.access_key_id, &resp.secret_access_key)
            .with_security_token(&resp.token)
            .with_expires_in(parse_rfc3339(&resp.expiration)?);

        cred.check()?;

        Ok(Some(cred))
    }

    async fn load_via_assume_role(&self) -> Result<Option<Credential>> {
        let role_arn = match &self.config.role_arn {
            Some(role_arn) => role_arn,
            None => return Ok(None),
        };
        let role_session_name = &self.config.role_session_name;

        let endpoint = self.sts_endpoint()?;

        // Construct request to AWS STS Service.
        let mut url = format!("https://{endpoint}/?Action=AssumeRole&RoleArn={role_arn}&Version=2011-06-15&RoleSessionName={role_session_name}");
        if let Some(external_id) = &self.config.external_id {
            write!(url, "&ExternalId={external_id}")?;
        }
        let req = self.client.get(&url).header(
            http::header::CONTENT_TYPE.as_str(),
            "application/x-www-form-urlencoded",
        );

        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!("request to AWS STS Services failed: {content}"));
        }

        let resp: AssumeRoleResponse = de::from_str(&resp.text().await?)?;
        let resp_cred = resp.result.credentials;

        let cred = Credential::new(&resp_cred.access_key_id, &resp_cred.secret_access_key)
            .with_security_token(&resp_cred.session_token)
            .with_expires_in(parse_rfc3339(&resp_cred.expiration)?);

        cred.check()?;

        Ok(Some(cred))
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

        let cred = Credential::new(&resp_cred.access_key_id, &resp_cred.secret_access_key)
            .with_security_token(&resp_cred.session_token)
            .with_expires_in(parse_rfc3339(&resp_cred.expiration)?);

        cred.check()?;

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

    use anyhow::Result;
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;
    use http::Request;
    use once_cell::sync::Lazy;
    use quick_xml::de;
    use reqwest::Client;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::aws::constants::*;

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
                let l = Loader::new(reqwest::Client::new(), Config::default())
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
                    let l = Loader::new(Client::new(), Config::default().from_env());
                    let x = l.load().await.expect("load must succeed");

                    let x = x.expect("must load succeed");
                    assert_eq!("access_key_id", x.access_key());
                    assert_eq!("secret_access_key", x.secret_key());
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
                    let l = Loader::new(Client::new(), Config::default().from_env().from_profile());
                    let x = l.load().await.unwrap().unwrap();
                    assert_eq!("config_access_key_id", x.access_key());
                    assert_eq!("config_secret_access_key", x.secret_key());
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
                    let l = Loader::new(Client::new(), Config::default().from_env().from_profile());
                    let x = l.load().await.unwrap().unwrap();
                    assert_eq!("shared_access_key_id", x.access_key());
                    assert_eq!("shared_secret_access_key", x.secret_key());
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
                    let l = Loader::new(Client::new(), Config::default().from_env().from_profile());
                    let x = l.load().await.expect("load must success").unwrap();
                    assert_eq!("shared_access_key_id", x.access_key());
                    assert_eq!("shared_secret_access_key", x.secret_key());
                })
            },
        );
    }

    #[tokio::test]
    async fn test_signer_with_web_loader() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        dotenv::from_filename(".env").ok();

        if env::var("REQSIGN_AWS_V4_TEST").is_err()
            || env::var("REQSIGN_AWS_V4_TEST").unwrap() != "on"
        {
            return Ok(());
        }

        let role_arn = env::var("REQSIGN_AWS_ROLE_ARN").expect("REQSIGN_AWS_ROLE_ARN not exist");
        let idp_url = env::var("REQSIGN_AWS_IDP_URL").expect("REQSIGN_AWS_IDP_URL not exist");
        let idp_content = BASE64_STANDARD
            .decode(env::var("REQSIGN_AWS_IDP_BODY").expect("REQSIGN_AWS_IDP_BODY not exist"))?;

        let client = Client::new();

        let mut req = Request::new(idp_content);
        *req.method_mut() = http::Method::POST;
        *req.uri_mut() = http::Uri::from_str(&idp_url)?;
        req.headers_mut()
            .insert(http::header::CONTENT_TYPE, "application/json".parse()?);

        #[derive(Deserialize)]
        struct Token {
            access_token: String,
        }
        let token = client
            .execute(req.try_into()?)
            .await?
            .json::<Token>()
            .await?
            .access_token;

        let file_path = format!(
            "{}/testdata/services/aws/web_identity_token_file",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );
        fs::write(&file_path, token)?;

        temp_env::with_vars(
            vec![
                ("AWS_ROLE_ARN", Some(&role_arn)),
                ("AWS_WEB_IDENTITY_TOKEN_FILE", Some(&file_path)),
            ],
            || {
                let l = Loader::new(Client::new(), Config::default().from_env());
                let x = RUNTIME
                    .block_on(l.load())
                    .expect("load_credential must success")
                    .unwrap();

                assert!(x.is_valid());
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
