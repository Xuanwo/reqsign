use std::fs;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::anyhow;
use anyhow::Result;
use http::header::AUTHORIZATION;
use http::header::CONTENT_LENGTH;
use http::header::CONTENT_TYPE;
use log::debug;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;

use super::config::Config;
use crate::time::now;
use crate::time::parse_rfc3339;
use crate::time::DateTime;

/// Credential for cos.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Credential {
    /// Secret ID
    pub secret_id: String,
    /// Secret Key
    pub secret_key: String,
    /// security_token
    pub security_token: Option<String>,
    /// expires in for credential.
    pub expires_in: Option<DateTime>,
}

/// CredentialLoader will load credential from different methods.
#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct CredentialLoader {
    client: Client,
    config: Config,

    credential: Arc<Mutex<Option<Credential>>>,
}

impl CredentialLoader {
    /// Create a new loader via config.
    pub fn new(client: Client, config: Config) -> Self {
        Self {
            client,
            config,

            credential: Arc::default(),
        }
    }

    /// Load credential
    pub async fn load(&self) -> Result<Option<Credential>> {
        // Return cached credential if it's valid.
        if let Some(cred) = self.credential.lock().expect("lock poisoned").clone() {
            return Ok(Some(cred));
        }

        let cred = self.load_inner().await?;

        let mut lock = self.credential.lock().expect("lock poisoned");
        *lock = cred.clone();

        Ok(cred)
    }

    async fn load_inner(&self) -> Result<Option<Credential>> {
        if let Ok(Some(cred)) = self
            .load_via_config()
            .map_err(|err| debug!("load credential via config failed: {err:?}"))
        {
            return Ok(Some(cred));
        }

        if let Ok(Some(cred)) = self
            .load_via_assume_role_with_web_identity()
            .await
            .map_err(|err| {
                debug!("load credential via assume_role_with_web_identity failed: {err:?}")
            })
        {
            return Ok(Some(cred));
        }

        Ok(None)
    }

    fn load_via_config(&self) -> Result<Option<Credential>> {
        if let (Some(ak), Some(sk)) = (&self.config.secret_id, &self.config.secret_key) {
            let cred = Credential {
                secret_id: ak.clone(),
                secret_key: sk.clone(),
                security_token: self.config.security_token.clone(),
                // Set expires_in to 10 minutes to enforce re-read
                // from file.
                expires_in: Some(now() + chrono::Duration::minutes(10)),
            };
            return Ok(Some(cred));
        }

        Ok(None)
    }

    async fn load_via_assume_role_with_web_identity(&self) -> Result<Option<Credential>> {
        let (region, token_file, role_arn, provider_id) = match (
            &self.config.region,
            &self.config.web_identity_token_file,
            &self.config.role_arn,
            &self.config.provider_id,
        ) {
            (Some(region), Some(token_file), Some(role_arn), Some(provider_id)) => {
                (region, token_file, role_arn, provider_id)
            }
            _ => {
                let missing = [
                    ("region", self.config.region.is_none()),
                    (
                        "web_identity_token_file",
                        self.config.web_identity_token_file.is_none(),
                    ),
                    ("role_arn", self.config.role_arn.is_none()),
                    ("provider_id", self.config.provider_id.is_none()),
                ]
                .iter()
                .filter_map(|&(k, v)| if v { Some(k) } else { None })
                .collect::<Vec<_>>()
                .join(", ");

                debug!(
                    "assume_role_with_web_identity is not configured fully: [{}] is missing",
                    missing
                );

                return Ok(None);
            }
        };

        let token = fs::read_to_string(token_file)?;
        let role_session_name = &self.config.role_session_name;

        // Construct request to Tencent Cloud STS Service.
        let url = "https://sts.tencentcloudapi.com".to_string();
        let bs = serde_json::to_vec(&AssumeRoleWithWebIdentityRequest {
            role_session_name: role_session_name.clone(),
            web_identity_token: token,
            role_arn: role_arn.clone(),
            provider_id: provider_id.clone(),
        })?;
        let req = self
            .client
            .post(&url)
            .header(AUTHORIZATION.as_str(), "SKIP")
            .header(CONTENT_TYPE.as_str(), "application/json")
            .header(CONTENT_LENGTH, bs.len())
            .header("X-TC-Action", "AssumeRoleWithWebIdentity")
            .header("X-TC-Region", region)
            .header("X-TC-Timestamp", now().timestamp())
            .header("X-TC-Version", "2018-08-13")
            .body(bs);

        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!(
                "request to Tencent Cloud STS Services failed: {content}"
            ));
        }

        let resp: AssumeRoleWithWebIdentityResult = serde_json::from_str(&resp.text().await?)?;
        if let Some(error) = resp.response.error {
            return Err(anyhow!(
                "request to Tencent Cloud STS Services failed: {error:?}"
            ));
        }
        let resp_expiration = resp.response.expiration;
        let resp_cred = resp.response.credentials;

        let cred = Credential {
            secret_id: resp_cred.tmp_secret_id,
            secret_key: resp_cred.tmp_secret_key,
            security_token: Some(resp_cred.token),
            expires_in: Some(parse_rfc3339(&resp_expiration)?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Serialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityRequest {
    role_session_name: String,
    web_identity_token: String,
    role_arn: String,
    provider_id: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResult {
    response: AssumeRoleWithWebIdentityResponse,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    error: Option<AssumeRoleWithWebIdentityError>,
    expiration: String,
    credentials: AssumeRoleWithWebIdentityCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityCredentials {
    token: String,
    tmp_secret_id: String,
    tmp_secret_key: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityError {
    code: String,
    message: String,
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::str::FromStr;

    use http::Request;
    use http::StatusCode;
    use log::debug;
    use once_cell::sync::Lazy;
    use tokio::runtime::Runtime;

    use super::super::constants::*;
    use super::super::cos::Signer;
    use super::*;

    static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Should create a tokio runtime")
    });

    #[test]
    fn test_parse_assume_role_with_web_identity() -> Result<()> {
        let content = r#"{
    "Response": {
        "ExpiredTime": 1543914376,
        "Expiration": "2018-12-04T09:06:16Z",
        "Credentials": {
            "Token": "1siMD5r0tPAq9xpR******6a1ad76f09a0069002923def8aFw7tUMd2nH",
            "TmpSecretId": "AKID65zyIP0mp****qt2SlWIQVMn1umNH58",
            "TmpSecretKey": "q95K84wrzuE****y39zg52boxvp71yoh"
        },
        "RequestId": "f6e7cbcb-add1-47bd-9097-d08cf8f3a919"
    }
}"#;

        let resp: AssumeRoleWithWebIdentityResult =
            serde_json::from_str(content).expect("json deserialize must success");

        assert_eq!(
            &resp.response.credentials.tmp_secret_id,
            "AKID65zyIP0mp****qt2SlWIQVMn1umNH58"
        );
        assert_eq!(
            &resp.response.credentials.tmp_secret_key,
            "q95K84wrzuE****y39zg52boxvp71yoh"
        );
        assert_eq!(
            &resp.response.credentials.token,
            "1siMD5r0tPAq9xpR******6a1ad76f09a0069002923def8aFw7tUMd2nH"
        );
        assert_eq!(&resp.response.expiration, "2018-12-04T09:06:16Z");

        Ok(())
    }

    #[test]
    fn test_signer_with_web_identidy_token() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        dotenv::from_filename(".env").ok();

        if env::var("REQSIGN_TENCENT_COS_TEST").is_err()
            || env::var("REQSIGN_TENCENT_COS_TEST").unwrap() != "on"
        {
            return Ok(());
        }

        // Ignore test if role_arn not set
        let role_arn = if let Ok(v) = env::var("REQSIGN_TENCENT_COS_ROLE_ARN") {
            v
        } else {
            return Ok(());
        };

        let provider_id = env::var("REQSIGN_TENCENT_COS_PROVIDER_ID")
            .expect("REQSIGN_TENCENT_COS_PROVIDER_ID not exist");
        let region =
            env::var("REQSIGN_TENCENT_COS_REGION").expect("REQSIGN_TENCENT_COS_REGION not exist");

        let github_token = env::var("GITHUB_ID_TOKEN").expect("GITHUB_ID_TOKEN not exist");
        let file_path = format!(
            "{}/testdata/services/tencent/web_identity_token_file",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );
        fs::write(&file_path, github_token)?;

        temp_env::with_vars(
            vec![
                (TENCENTCLOUD_REGION, Some(&region)),
                (TENCENTCLOUD_ROLE_ARN, Some(&role_arn)),
                (TENCENTCLOUD_PROVIDER_ID, Some(&provider_id)),
                (TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE, Some(&file_path)),
            ],
            || {
                RUNTIME.block_on(async {
                    let config = Config::default().from_env();
                    let loader = CredentialLoader::new(reqwest::Client::new(), config);

                    let signer = Signer::new();

                    let url = &env::var("REQSIGN_TENCENT_COS_URL")
                        .expect("env REQSIGN_TENCENT_COS_URL must set");

                    let mut req = Request::new("");
                    *req.method_mut() = http::Method::GET;
                    *req.uri_mut() = http::Uri::from_str(&format!("{}/{}", url, "not_exist_file"))
                        .expect("must valid");

                    let cred = loader
                        .load()
                        .await
                        .expect("credential must be valid")
                        .unwrap();

                    signer
                        .sign(&mut req, &cred)
                        .expect("sign request must success");

                    debug!("signed request url: {:?}", req.uri().to_string());
                    debug!("signed request: {:?}", req);

                    let client = reqwest::Client::new();
                    let resp = client
                        .execute(req.try_into().unwrap())
                        .await
                        .expect("request must succeed");

                    let status = resp.status();
                    debug!("got response: {:?}", resp);
                    debug!("got response content: {}", resp.text().await.unwrap());
                    assert_eq!(StatusCode::NOT_FOUND, status);
                })
            },
        );

        Ok(())
    }
}
