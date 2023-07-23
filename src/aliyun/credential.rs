use std::fs;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::anyhow;
use anyhow::Result;
use log::debug;
use reqwest::Client;
use serde::Deserialize;

use super::config::Config;
use crate::time::format_rfc3339;
use crate::time::now;
use crate::time::parse_rfc3339;
use crate::time::DateTime;

/// Credential that holds the access_key and secret_key.
#[derive(Default, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Credential {
    /// Access key id for credential.
    pub access_key_id: String,
    /// Access key secret for credential.
    pub access_key_secret: String,
    /// Security token for credential.
    pub security_token: Option<String>,
    /// expires in for credential.
    pub expires_in: Option<DateTime>,
}

impl Credential {
    /// is current cred is valid?
    pub fn is_valid(&self) -> bool {
        if (self.access_key_id.is_empty() || self.access_key_secret.is_empty())
            && self.security_token.is_none()
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

/// Loader will load credential from different methods.
#[cfg_attr(test, derive(Debug))]
pub struct Loader {
    client: Client,
    config: Config,

    credential: Arc<Mutex<Option<Credential>>>,
}

impl Loader {
    /// Create a new loader via client and config.
    pub fn new(client: Client, config: Config) -> Self {
        Self {
            client,
            config,

            credential: Arc::default(),
        }
    }

    /// Load credential.
    pub async fn load(&self) -> Result<Option<Credential>> {
        // Return cached credential if it's valid.
        match self.credential.lock().expect("lock poisoned").clone() {
            Some(cred) if cred.is_valid() => return Ok(Some(cred)),
            _ => (),
        }

        let cred = if let Some(cred) = self.load_inner().await? {
            cred
        } else {
            return Ok(None);
        };

        let mut lock = self.credential.lock().expect("lock poisoned");
        *lock = Some(cred.clone());

        Ok(Some(cred))
    }

    async fn load_inner(&self) -> Result<Option<Credential>> {
        if let Ok(Some(cred)) = self
            .load_via_static()
            .map_err(|err| debug!("load credential via static failed: {err:?}"))
        {
            return Ok(Some(cred));
        }

        if let Ok(Some(cred)) = self
            .load_via_assume_role_with_oidc()
            .await
            .map_err(|err| debug!("load credential load via assume_role_with_oidc: {err:?}"))
        {
            return Ok(Some(cred));
        }

        Ok(None)
    }

    fn load_via_static(&self) -> Result<Option<Credential>> {
        if let (Some(ak), Some(sk)) = (&self.config.access_key_id, &self.config.access_key_secret) {
            Ok(Some(Credential {
                access_key_id: ak.clone(),
                access_key_secret: sk.clone(),
                security_token: self.config.security_token.clone(),
                // Set expires_in to 10 minutes to enforce re-read
                // from file.
                expires_in: Some(now() + chrono::Duration::minutes(10)),
            }))
        } else {
            Ok(None)
        }
    }

    async fn load_via_assume_role_with_oidc(&self) -> Result<Option<Credential>> {
        let (token_file, role_arn, provider_arn) = match (
            &self.config.oidc_token_file,
            &self.config.role_arn,
            &self.config.oidc_provider_arn,
        ) {
            (Some(token_file), Some(role_arn), Some(provider_arn)) => {
                (token_file, role_arn, provider_arn)
            }
            _ => return Ok(None),
        };

        let token = fs::read_to_string(token_file)?;
        let role_session_name = &self.config.role_session_name;

        // Construct request to Aliyun STS Service.
        let url = format!("https://sts.aliyuncs.com/?Action=AssumeRoleWithOIDC&OIDCProviderArn={}&RoleArn={}&RoleSessionName={}&Format=JSON&Version=2015-04-01&Timestamp={}&OIDCToken={}", provider_arn, role_arn, role_session_name, format_rfc3339(now()), token);

        let req = self.client.get(&url).header(
            http::header::CONTENT_TYPE.as_str(),
            "application/x-www-form-urlencoded",
        );

        let resp = req.send().await?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.text().await?;
            return Err(anyhow!("request to Aliyun STS Services failed: {content}"));
        }

        let resp: AssumeRoleWithOidcResponse = serde_json::from_slice(&resp.bytes().await?)?;
        let resp_cred = resp.credentials;

        let cred = Credential {
            access_key_id: resp_cred.access_key_id,
            access_key_secret: resp_cred.access_key_secret,
            security_token: Some(resp_cred.security_token),
            expires_in: Some(parse_rfc3339(&resp_cred.expiration)?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default)]
struct AssumeRoleWithOidcResponse {
    #[serde(rename = "Credentials")]
    credentials: AssumeRoleWithOidcCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithOidcCredentials {
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
    expiration: String,
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::str::FromStr;
    use std::time::Duration;

    use http::Request;
    use http::StatusCode;
    use log::debug;
    use once_cell::sync::Lazy;
    use reqwest::blocking::Client;
    use tokio::runtime::Runtime;

    use super::super::constants::*;
    use super::super::oss::Signer;
    use super::*;

    static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Should create a tokio runtime")
    });

    #[test]
    fn test_parse_assume_role_with_oidc_response() -> Result<()> {
        let content = r#"{
    "RequestId": "3D57EAD2-8723-1F26-B69C-F8707D8B565D",
    "OIDCTokenInfo": {
        "Subject": "KryrkIdjylZb7agUgCEf****",
        "Issuer": "https://dev-xxxxxx.okta.com",
        "ClientIds": "496271242565057****"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "33157794895460****",
        "Arn": "acs:ram::113511544585****:role/testoidc/TestOidcAssumedRoleSession"
    },
    "Credentials": {
        "SecurityToken": "CAIShwJ1q6Ft5B2yfSjIr5bSEsj4g7BihPWGWHz****",
        "Expiration": "2021-10-20T04:27:09Z",
        "AccessKeySecret": "CVwjCkNzTMupZ8NbTCxCBRq3K16jtcWFTJAyBEv2****",
        "AccessKeyId": "STS.NUgYrLnoC37mZZCNnAbez****"
    }
}"#;

        let resp: AssumeRoleWithOidcResponse =
            serde_json::from_str(content).expect("json deserialize must success");

        assert_eq!(
            &resp.credentials.access_key_id,
            "STS.NUgYrLnoC37mZZCNnAbez****"
        );
        assert_eq!(
            &resp.credentials.access_key_secret,
            "CVwjCkNzTMupZ8NbTCxCBRq3K16jtcWFTJAyBEv2****"
        );
        assert_eq!(
            &resp.credentials.security_token,
            "CAIShwJ1q6Ft5B2yfSjIr5bSEsj4g7BihPWGWHz****"
        );
        assert_eq!(&resp.credentials.expiration, "2021-10-20T04:27:09Z");

        Ok(())
    }

    #[test]
    fn test_signer_with_oidc() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        dotenv::from_filename(".env").ok();

        if env::var("REQSIGN_ALIYUN_OSS_TEST").is_err()
            || env::var("REQSIGN_ALIYUN_OSS_TEST").unwrap() != "on"
        {
            return Ok(());
        }

        let provider_arn =
            env::var("REQSIGN_ALIYUN_PROVIDER_ARN").expect("REQSIGN_ALIYUN_PROVIDER_ARN not exist");
        let role_arn =
            env::var("REQSIGN_ALIYUN_ROLE_ARN").expect("REQSIGN_ALIYUN_ROLE_ARN not exist");
        let idp_url = env::var("REQSIGN_ALIYUN_IDP_URL").expect("REQSIGN_ALIYUN_IDP_URL not exist");
        let idp_content =
            env::var("REQSIGN_ALIYUN_IDP_BODY").expect("REQSIGN_ALIYUN_IDP_BODY not exist");

        let mut req = Request::new(idp_content);
        *req.method_mut() = http::Method::POST;
        *req.uri_mut() = http::Uri::from_str(&idp_url)?;
        req.headers_mut().insert(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse()?,
        );

        #[derive(Deserialize)]
        struct Token {
            id_token: String,
        }
        let token = Client::new()
            .execute(req.try_into()?)?
            .json::<Token>()?
            .id_token;

        let file_path = format!(
            "{}/testdata/services/aliyun/oidc_token_file",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );
        fs::write(&file_path, token)?;

        temp_env::with_vars(
            vec![
                (ALIBABA_CLOUD_ROLE_ARN, Some(&role_arn)),
                (ALIBABA_CLOUD_OIDC_PROVIDER_ARN, Some(&provider_arn)),
                (ALIBABA_CLOUD_OIDC_TOKEN_FILE, Some(&file_path)),
            ],
            || {
                RUNTIME.block_on(async {
                    let config = Config::default().from_env();
                    let loader = Loader::new(reqwest::Client::new(), config);

                    let signer = Signer::new(
                        &env::var("REQSIGN_ALIYUN_OSS_BUCKET")
                            .expect("env REQSIGN_ALIYUN_OSS_BUCKET must set"),
                    );

                    let url = &env::var("REQSIGN_ALIYUN_OSS_URL")
                        .expect("env REQSIGN_ALIYUN_OSS_URL must set");

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

    #[test]
    fn test_signer_with_oidc_query() -> Result<()> {
        let _ = env_logger::builder().try_init();

        dotenv::from_filename(".env").ok();

        if env::var("REQSIGN_ALIYUN_OSS_TEST").is_err()
            || env::var("REQSIGN_ALIYUN_OSS_TEST").unwrap() != "on"
        {
            return Ok(());
        }

        let provider_arn =
            env::var("REQSIGN_ALIYUN_PROVIDER_ARN").expect("REQSIGN_ALIYUN_PROVIDER_ARN not exist");
        let role_arn =
            env::var("REQSIGN_ALIYUN_ROLE_ARN").expect("REQSIGN_ALIYUN_ROLE_ARN not exist");
        let idp_url = env::var("REQSIGN_ALIYUN_IDP_URL").expect("REQSIGN_ALIYUN_IDP_URL not exist");
        let idp_content =
            env::var("REQSIGN_ALIYUN_IDP_BODY").expect("REQSIGN_ALIYUN_IDP_BODY not exist");

        let mut req = Request::new(idp_content);
        *req.method_mut() = http::Method::POST;
        *req.uri_mut() = http::Uri::from_str(&idp_url)?;
        req.headers_mut().insert(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse()?,
        );

        #[derive(Deserialize)]
        struct Token {
            id_token: String,
        }
        let token = Client::new()
            .execute(req.try_into()?)?
            .json::<Token>()?
            .id_token;

        let file_path = format!(
            "{}/testdata/services/aliyun/oidc_token_file",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );
        fs::write(&file_path, token)?;

        temp_env::with_vars(
            vec![
                (ALIBABA_CLOUD_ROLE_ARN, Some(&role_arn)),
                (ALIBABA_CLOUD_OIDC_PROVIDER_ARN, Some(&provider_arn)),
                (ALIBABA_CLOUD_OIDC_TOKEN_FILE, Some(&file_path)),
            ],
            || {
                RUNTIME.block_on(async {
                    let config = Config::default().from_env();
                    let loader = Loader::new(reqwest::Client::new(), config);

                    let signer = Signer::new(
                        &env::var("REQSIGN_ALIYUN_OSS_BUCKET")
                            .expect("env REQSIGN_ALIYUN_OSS_BUCKET must set"),
                    );

                    let url = &env::var("REQSIGN_ALIYUN_OSS_URL")
                        .expect("env REQSIGN_ALIYUN_OSS_URL must set");

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
                        .sign_query(&mut req, Duration::from_secs(3600), &cred)
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
