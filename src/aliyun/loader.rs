use std::fs;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::sleep;

use anyhow::anyhow;
use anyhow::Result;
use backon::BackoffBuilder;
use backon::ExponentialBuilder;
use log::warn;
use reqwest::Client;
use serde::Deserialize;

use super::config::Config;
use crate::credential::Credential;
use crate::time::format_rfc3339;
use crate::time::now;
use crate::time::parse_rfc3339;

/// Loader will load credential from different methods.
#[cfg_attr(test, derive(Debug))]
pub struct Loader {
    credential: Arc<Mutex<Option<Credential>>>,

    disable_env: bool,
    disable_assume_role_with_oidc: bool,

    client: Client,
    config: Config,
}

impl Loader {
    /// Create a new loader via client and config.
    pub fn new(client: Client, config: Config) -> Self {
        Self {
            client,
            config,

            credential: Arc::default(),
            disable_env: false,
            disable_assume_role_with_oidc: false,
        }
    }

    /// Disable load from env.
    pub fn with_disable_env(mut self) -> Self {
        self.disable_env = true;
        self
    }

    /// Disable load from assume role with oidc.
    pub fn with_disable_assume_role_with_oidc(mut self) -> Self {
        self.disable_assume_role_with_oidc = true;
        self
    }

    /// Load credential.
    pub async fn load(&self) -> Option<Credential> {
        // Return cached credential if it's valid.
        match self.credential.lock().expect("lock poisoned").clone() {
            Some(cred) if cred.is_valid() => return Some(cred),
            _ => (),
        }

        // Let's retry 4 times: 1s -> 2s -> 4s -> 8s.
        let mut retry = ExponentialBuilder::default()
            .with_max_times(4)
            .with_jitter()
            .build();

        let cred = loop {
            let cred = self.load_via_env();

            let cred = if cred.is_some() {
                cred
            } else {
                self.load_via_assume_role_with_oidc()
                    .await
                    .map_err(|err| {
                        warn!("load credential via assume role with oidc failed: {err:?}");
                        err
                    })
                    .unwrap_or_default()
            };

            match cred {
                Some(cred) => break cred,
                None => match retry.next() {
                    Some(dur) => {
                        sleep(dur);
                        continue;
                    }
                    None => {
                        warn!("load credential still failed after retry");
                        return None;
                    }
                },
            }
        };

        let mut lock = self.credential.lock().expect("lock poisoned");
        *lock = Some(cred.clone());

        Some(cred)
    }

    fn load_via_env(&self) -> Option<Credential> {
        if self.disable_env {
            return None;
        }

        if let (Some(ak), Some(sk)) = (&self.config.access_key_id, &self.config.access_key_secret) {
            let mut cred = Credential::new(ak, sk);
            if let Some(tk) = &self.config.security_token {
                cred.set_security_token(tk);
            }
            Some(cred)
        } else {
            None
        }
    }

    async fn load_via_assume_role_with_oidc(&self) -> Result<Option<Credential>> {
        if self.disable_assume_role_with_oidc {
            return Ok(None);
        }

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
        let role_session_name = self
            .config
            .role_session_name
            .as_deref()
            .unwrap_or("reqsign");

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

        let cred = Credential::new(&resp_cred.access_key_id, &resp_cred.access_key_secret)
            .with_security_token(&resp_cred.security_token)
            .with_expires_in(parse_rfc3339(&resp_cred.expiration)?);

        cred.check()?;

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

    use http::Request;
    use once_cell::sync::Lazy;
    use reqwest::blocking::Client;
    use time::Duration;
    use tokio::runtime::Runtime;

    use super::super::constants::*;
    use super::super::oss::Signer;
    use super::*;
    use log::debug;

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

    #[tokio::test]
    async fn test_signer_with_oidc() -> Result<()> {
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
                    let l = Loader::new(reqwest::Client::new(), Config::default().from_env());
                    let x = l.load().await.expect("credential must be valid");

                    assert!(x.is_valid());
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

                    let cred = loader.load().await.expect("credential must be valid");

                    signer
                        .sign_query(&mut req, Duration::seconds(3600), &cred)
                        .expect("sign request must success");

                    debug!("signed request url: {:?}", req.uri().to_string());
                    debug!("signed request: {:?}", req);
                })
            },
        );
        Ok(())
    }
}
